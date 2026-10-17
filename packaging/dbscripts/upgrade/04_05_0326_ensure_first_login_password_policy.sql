--
-- Copyright 새올정보기술 (OV-Works), 2026
-- SPDX-License-Identifier: Apache-2.0
--
-- Keep this in a new upgrade step: installations that already executed the
-- original password-policy migration still need the option to be registered.
select fn_db_add_config_value(
    'PasswordPolicyForceChangeOnFirstLogin',
    'false',
    'general'
);
