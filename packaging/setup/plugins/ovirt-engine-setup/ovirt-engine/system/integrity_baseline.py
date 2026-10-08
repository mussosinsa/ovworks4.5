#
# ovirt-engine-setup -- ovirt engine setup
#
# Copyright oVirt Authors
# SPDX-License-Identifier: Apache-2.0
#
#


"""Integrity verification baseline plugin."""


import gettext
import os

from otopi import plugin
from otopi import util

from ovirt_engine_setup import aide as oaide
from ovirt_engine_setup import constants as osetupcons
from ovirt_engine_setup.engine import constants as oenginecons
from ovirt_engine_setup.engine_common import constants as oengcommcons


def _(m):
    return gettext.dgettext(message=m, domain='ovirt-engine-setup')


# config/client_control.py: the database credentials are encrypted in place in closeup, and the
# baseline has to be taken of the files as they are left, not as they were a moment before.
_DB_CREDENTIALS_ENCRYPTED = 'osetup.db.connection.credentials.encrypted'

# This plugin's own closeup, which the summary of what went wrong in it follows.
_BASELINE_TAKEN = 'osetup.engine.integrity.baseline'

# The second attempt, for an AIDE that was installed later in the same run.
_BASELINE_RETRIED = 'osetup.engine.integrity.baseline.retried'


@util.export
class Plugin(plugin.PluginBase):
    """Writes the integrity verification's AIDE configuration and takes its baseline.

    The verification measures the files of the six main processes by exact name (see
    ovirt_engine_setup/aide.py). engine-setup is what changes those files in approved work -
    configuration, certificates, encrypted credentials, an upgrade's new program files - so the
    baseline is taken again at the end of every run, once all of them have been written and
    before the engine starts and verifies against it.
    """

    def __init__(self, context):
        super(Plugin, self).__init__(context=context)
        # What kept the verification from being ready, said again in the summary: a warning in
        # the middle of the closeup scrolls past, and the host then runs with a verification that
        # can only ever report that it could not check anything.
        self._problems = []
        # Set when AIDE was not there when the baseline was due: something later in the same
        # run (a site's own setup step) may install it, and the baseline is tried again then.
        self._retry = None

    def _problem(self, message):
        self.logger.error(message)
        self._problems.append(message)

    @plugin.event(
        stage=plugin.Stages.STAGE_MISC,
        condition=lambda self: (
            self.environment[oenginecons.CoreEnv.ENABLE] and
            not self.environment[osetupcons.CoreEnv.DEVELOPER_MODE]
        ),
    )
    def _misc(self):
        # Before the verification had a configuration of its own, engine-setup added its rules
        # to the distribution's /etc/aide.conf. Taken out, leaving the file as the aide package
        # left it: the verification no longer reads it.
        path = oaide.Aide.LEGACY_CONFIG_PATH
        try:
            with open(path, encoding='utf-8') as stream:
                content = stream.read()
        except OSError:
            return
        without = oaide.Aide.without_legacy_block(content)
        if without == content:
            return
        self.logger.info(_('Removing oVirt Engine rules from %s'), path)
        with open(path, 'w', encoding='utf-8') as stream:
            stream.write(without)

    @plugin.event(
        stage=plugin.Stages.STAGE_CLOSEUP,
        name=_BASELINE_TAKEN,
        after=(
            _DB_CREDENTIALS_ENCRYPTED,
            oaide.Aide.SUDOERS_WRITTEN_EVENT,
        ),
        before=(
            oengcommcons.Stages.CORE_ENGINE_START,
        ),
        condition=lambda self: (
            self.environment[oenginecons.CoreEnv.ENABLE] and
            not self.environment[osetupcons.CoreEnv.DEVELOPER_MODE]
        ),
    )
    def _closeup(self):
        try:
            entries = oaide.ProcessFiles.read()
        except (OSError, ValueError) as e:
            self._problem(
                _(
                    'The integrity verification has no list of files to measure '
                    '({path}: {error}); its baseline was not taken'
                ).format(path=oaide.ProcessFiles.LIST_PATH, error=e)
            )
            return

        # Written when every file it names is in place, so that it says which of them exist.
        config = oaide.Aide.CONFIG_PATH
        content = oaide.Aide.config(entries)
        os.makedirs(os.path.dirname(config), mode=0o755, exist_ok=True)
        with open(config, 'w', encoding='utf-8') as stream:
            stream.write(content)
        # Readable by the engine, which reads in it which process each file belongs to. It
        # holds no secret: only the names of package and configuration files.
        os.chmod(config, 0o644)

        if not os.path.exists(oaide.Aide.COMMAND):
            self.logger.info(
                _(
                    'AIDE is not installed yet ({command}); the integrity verification '
                    'baseline will be taken again at the end of setup'
                ).format(command=oaide.Aide.COMMAND)
            )
            self._retry = (content, config)
            return
        self._take_baseline(content, config)

    @plugin.event(
        stage=plugin.Stages.STAGE_CLOSEUP,
        name=_BASELINE_RETRIED,
        after=(
            _BASELINE_TAKEN,
            oengcommcons.Stages.CORE_ENGINE_START,
        ),
        # The summary's title comes before the engine is started; its end comes after, and what
        # went wrong here has to be known by then.
        before=(
            osetupcons.Stages.DIALOG_TITLES_E_SUMMARY,
        ),
        condition=lambda self: self._retry is not None,
    )
    def _closeup_retry(self):
        # After every other step of the run, any that installs AIDE included. The engine has
        # started by now, and verifies a couple of minutes after it does; the baseline of the
        # few files measured is taken and sealed in seconds, well before that.
        content, config = self._retry
        self._retry = None
        if not os.path.exists(oaide.Aide.COMMAND):
            self._problem(
                _(
                    'AIDE is not installed ({command}); the integrity verification of '
                    'the main processes cannot run until it is and engine-setup is run again'
                ).format(command=oaide.Aide.COMMAND)
            )
            return
        self.logger.info(_('AIDE is now installed; taking the integrity verification baseline'))
        self._take_baseline(content, config)

    def _take_baseline(self, content, config):
        os.makedirs(os.path.dirname(oaide.Aide.DATABASE), mode=0o700, exist_ok=True)
        if os.path.exists(oaide.Aide.DATABASE_NEW):
            os.unlink(oaide.Aide.DATABASE_NEW)
        rc, stdout, stderr = self.execute(
            oaide.Aide.init_command(),
            raiseOnError=False,
        )
        if rc != 0 or not os.path.exists(oaide.Aide.DATABASE_NEW):
            # Said, not raised: the rest of engine-setup has been done and is not undone by
            # this. The verification then reports that it could not be carried out.
            self._problem(
                _(
                    'The integrity verification baseline could not be taken '
                    '(AIDE exit code {rc}): {error}'
                ).format(
                    rc=rc,
                    error='\n'.join(stderr or stdout or []).strip(),
                )
            )
            return
        # The seal of the baseline being replaced goes with it. Left in place, a seal that then
        # could not be renewed would no longer match the new baseline, and every verification
        # would report the baseline as altered - a finding, which stops the engine - when all
        # that happened is that it was not sealed.
        if os.path.exists(oaide.Aide.SEAL):
            os.unlink(oaide.Aide.SEAL)
        os.replace(oaide.Aide.DATABASE_NEW, oaide.Aide.DATABASE)
        os.chmod(oaide.Aide.DATABASE, 0o600)
        # Sealed under the DEK, so that the baseline and its configuration cannot be rewritten to
        # match altered files without the KEK passphrase. Said, not raised, when it cannot be:
        # every verification then reports that it could not check the seal.
        rc, stdout, stderr = self.execute(
            oaide.Aide.seal_command(),
            raiseOnError=False,
        )
        if rc != 0 or not os.path.exists(oaide.Aide.SEAL):
            self._problem(
                _(
                    'The integrity verification baseline could not be sealed: {error}. '
                    'Every verification will report that it cannot check the baseline '
                    'until engine-setup seals it'
                ).format(error='\n'.join(stderr or stdout or []).strip())
            )
        self.logger.info(
            _(
                'Integrity verification baseline taken: {count} file(s) of the main '
                'processes ({config})'
            ).format(count=config_measured(content), config=config)
        )

    @plugin.event(
        stage=plugin.Stages.STAGE_CLOSEUP,
        before=(
            osetupcons.Stages.DIALOG_TITLES_E_SUMMARY,
        ),
        after=(
            osetupcons.Stages.DIALOG_TITLES_S_SUMMARY,
            _BASELINE_TAKEN,
            _BASELINE_RETRIED,
        ),
        condition=lambda self: bool(self._problems),
    )
    def _summary(self):
        self.dialog.note(
            text=_(
                '!! The integrity verification is NOT ready. Until this is corrected every '
                'verification reports that it could not be carried out (it is alerted, the '
                'engine is not stopped). Correct the cause and run engine-setup again:'
            ),
        )
        for problem in self._problems:
            self.dialog.note(text='   - ' + problem)


def config_measured(content):
    """@return how many files the configuration measures"""
    return sum(
        1 for line in content.splitlines()
        if line.startswith(oaide.Aide.MEASURED + ' ')
    )


# vim: expandtab tabstop=4 shiftwidth=4
