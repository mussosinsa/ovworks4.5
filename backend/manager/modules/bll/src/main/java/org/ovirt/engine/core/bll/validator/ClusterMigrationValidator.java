package org.ovirt.engine.core.bll.validator;

import org.ovirt.engine.core.bll.ValidationResult;
import org.ovirt.engine.core.common.config.Config;
import org.ovirt.engine.core.common.config.ConfigValues;
import org.ovirt.engine.core.common.errors.EngineMessage;
import org.ovirt.engine.core.compat.Guid;
import org.ovirt.engine.core.dao.VdsDao;
import org.ovirt.engine.core.di.Injector;
import org.ovirt.engine.core.utils.ReplacementUtils;

/**
 * Whether a cluster is one that a migration may be asked for within.
 *
 * <p>Here rather than in either command, because both of them are asked: a migration of one machine
 * and a migration of several arrive as different commands, and a rule one of them applies is a rule
 * the other one is a way around.</p>
 */
public class ClusterMigrationValidator {

    private static final String VAR_MINIMUM_HOSTS = "minimumHosts"; //$NON-NLS-1$

    private static final String VAR_CLUSTER_HOSTS = "clusterHosts"; //$NON-NLS-1$

    private final Guid clusterId;

    public ClusterMigrationValidator(Guid clusterId) {
        this.clusterId = clusterId;
    }

    /** @return the cluster this is asking about */
    public Guid getClusterId() {
        return clusterId;
    }

    /**
     * @return an error if the cluster is too small for a migration within it to be asked for
     *
     * <p>A decision about how the estate is run rather than about what is possible. Two hosts can
     * move a machine between them and nothing else refuses it, but a pair has nowhere to put the
     * machine when the other one is the reason it is being moved, and offering the action on a
     * cluster that small invites the move that cannot help.
     * {@link ConfigValues#MinimumHostsForMigration} is where the line is; setting it to 2 puts a
     * pair back, and to 1 takes the rule away.</p>
     */
    public ValidationResult hasEnoughHostsToMigrateWithin() {
        int minimum = minimumHosts();
        if (minimum <= 1) {
            return ValidationResult.VALID;
        }
        int hosts = getVdsDao().getAllForCluster(clusterId).size();
        if (hosts >= minimum) {
            return ValidationResult.VALID;
        }
        return new ValidationResult(EngineMessage.ACTION_TYPE_FAILED_NOT_ENOUGH_HOSTS_FOR_MIGRATION,
                ReplacementUtils.createSetVariableString(VAR_MINIMUM_HOSTS, minimum),
                ReplacementUtils.createSetVariableString(VAR_CLUSTER_HOSTS, hosts));
    }

    /**
     * @return what {@link ConfigValues#MinimumHostsForMigration} is set to
     *
     * <p>One or less is no rule at all rather than a rule that always passes: an installation that
     * wants the engine's own judgement back sets it there, and saying so here is what keeps the
     * database from being asked how large a cluster is in order to compare it with a number that
     * cannot fail.</p>
     */
    protected int minimumHosts() {
        return Config.<Integer> getValue(ConfigValues.MinimumHostsForMigration);
    }

    protected VdsDao getVdsDao() {
        return Injector.get(VdsDao.class);
    }
}
