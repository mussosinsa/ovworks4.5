package org.ovirt.engine.core.sso.db;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import javax.enterprise.context.ApplicationScoped;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.sql.DataSource;

import org.apache.commons.lang.StringUtils;
import org.ovirt.engine.core.sso.api.ClientInfo;
import org.ovirt.engine.core.sso.api.LoginFailureRecord;
import org.ovirt.engine.core.sso.service.SsoService;
import org.ovirt.engine.core.uutils.security.PasswordHistoryEntry;

@ApplicationScoped
public class SsoDao {
    public static final String DATA_SOURCE = "java:/ENGINEDataSource";
    public static final String GET_CLIENT_INFO_SQL =
            "SELECT client_id, client_secret, certificate_location, callback_prefix, encrypted_userinfo, " +
                    "notification_callback, scope, trusted, notification_callback_protocol, " +
                    "notification_callback_verify_host, notification_callback_verify_chain " +
                    "FROM sso_clients";

    public Map<String, ClientInfo> getAllSsoClientsInfo() {
        return executeQuery(ds -> {
            Map<String, ClientInfo> map = new HashMap<>();
            try (
                    Connection connection = ds.getConnection();
                    PreparedStatement ps = connection.prepareStatement(GET_CLIENT_INFO_SQL)) {
                try (ResultSet rs = ps.executeQuery()) {

                    while (rs.next()) {
                        ClientInfo clientInfo = ClientInfoMapper.INSTANCE.apply(rs);
                        map.put(clientInfo.getClientId(), clientInfo);
                    }
                }
            }
            return map;
        }, "Unable to initialize client registry");
    }

    public ClientInfo getSsoClientInfo(String clientId) {
        return executeQuery(ds -> {
            try (
                    Connection connection = ds.getConnection();
                    PreparedStatement ps = connection.prepareStatement(GET_CLIENT_INFO_SQL + " WHERE client_id = ?");) {
                ps.setString(1, clientId);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return ClientInfoMapper.INSTANCE.apply(rs);
                    }
                }
            }
            return null;
        }, "Unable to find client info for client id " + clientId);
    }


    public String getVdcOptionValue(String optionName) {
        return executeQuery(ds -> {
            String sql = "SELECT option_value FROM vdc_options WHERE option_name = ? ORDER BY option_id DESC LIMIT 1";
            try (
                    Connection connection = ds.getConnection();
                    PreparedStatement ps = connection.prepareStatement(sql)) {
                ps.setString(1, optionName);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return rs.getString("option_value");
                    }
                }
            }
            return null;
        }, "Unable to find vdc option value for option " + optionName);
    }

    /**
     * @param principal the normalized 'name@realm' key, see PasswordHistoryCryptor.principalKey()
     * @param limit maximum number of entries to read
     * @return the password history of the account, most recent first
     */
    public List<PasswordHistoryEntry> getUserPasswordHistory(String principal, int limit) {
        return executeQuery(ds -> {
            List<PasswordHistoryEntry> history = new ArrayList<>();
            String sql = "SELECT password_hash, change_date FROM user_password_history " +
                    "WHERE principal = ? ORDER BY change_date DESC LIMIT ?";
            try (
                    Connection connection = ds.getConnection();
                    PreparedStatement ps = connection.prepareStatement(sql)) {
                ps.setString(1, principal);
                ps.setInt(2, limit);
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        Timestamp changeDate = rs.getTimestamp("change_date");
                        if (changeDate != null) {
                            history.add(new PasswordHistoryEntry(
                                    rs.getString("password_hash"),
                                    changeDate.toInstant()));
                        }
                    }
                }
            }
            return history;
        }, "Unable to read the password history of " + principal);
    }

    public boolean isUserPasswordHistoryAvailable() {
        return executeQuery(ds -> {
            String sql = "SELECT to_regclass('public.user_password_history') IS NOT NULL";
            try (
                    Connection connection = ds.getConnection();
                    PreparedStatement ps = connection.prepareStatement(sql);
                    ResultSet rs = ps.executeQuery()) {
                return rs.next() && rs.getBoolean(1);
            }
        }, "Unable to check password history availability");
    }

    /**
     * Remembers a password that was just set, so the reuse policies can see it later.
     */
    public void insertUserPasswordHistory(String principal, String passwordHash, Instant changeDate) {
        executeQuery(ds -> {
            String sql = "INSERT INTO user_password_history (principal, password_hash, change_date) " +
                    "VALUES (?, ?, ?)";
            try (
                    Connection connection = ds.getConnection();
                    PreparedStatement ps = connection.prepareStatement(sql)) {
                ps.setString(1, principal);
                ps.setString(2, passwordHash);
                ps.setTimestamp(3, Timestamp.from(changeDate));
                ps.executeUpdate();
            }
            return null;
        }, "Unable to record the password history of " + principal);
    }

    /**
     * Drops the entries that are both older than the threshold and outside the newest
     * {@code keep} ones, so a history can not grow without bound.
     */
    public void cleanupUserPasswordHistory(String principal, Instant threshold, int keep) {
        executeQuery(ds -> {
            String sql = "DELETE FROM user_password_history WHERE principal = ? AND change_date < ? " +
                    "AND id NOT IN (SELECT id FROM user_password_history WHERE principal = ? " +
                    "ORDER BY change_date DESC LIMIT ?)";
            try (
                    Connection connection = ds.getConnection();
                    PreparedStatement ps = connection.prepareStatement(sql)) {
                ps.setString(1, principal);
                ps.setTimestamp(2, Timestamp.from(threshold));
                ps.setString(3, principal);
                ps.setInt(4, keep);
                ps.executeUpdate();
            }
            return null;
        }, "Unable to clean up the password history of " + principal);
    }

    /**
     * @param principal the normalized 'name@profile' key, see AuthenticationService.principalKey()
     * @return what has been counted against the account, or null when nothing has
     */
    public LoginFailureRecord getLoginFailures(String principal) {
        return executeQuery(ds -> {
            String sql = "SELECT failure_count, locked_until FROM user_login_failures WHERE principal = ?";
            try (
                    Connection connection = ds.getConnection();
                    PreparedStatement ps = connection.prepareStatement(sql)) {
                ps.setString(1, principal);
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next() ? loginFailureRecordOf(rs) : null;
                }
            }
        }, "Unable to read the login failures of " + principal);
    }

    /**
     * Counts one failed password attempt against the account and locks it once there have been
     * {@code maxFailures} of them.
     *
     * <p>The counting is left to the database rather than done here, so that attempts arriving at
     * the same moment - which is what a password guesser produces - are counted once each. A lock
     * already in force is returned as it stands: it is neither extended nor counted against, so
     * that guessing on through a lock cannot keep the account locked indefinitely. A lock that has
     * run out is cleared by the same statement, and the attempt clearing it starts a fresh count.</p>
     *
     * @param principal the normalized 'name@profile' key
     * @param loginName the name part of that key, by which the lock can be lifted from the user list
     * @return what is now counted against the account
     */
    public LoginFailureRecord recordLoginFailure(
            String principal,
            String loginName,
            Instant now,
            int maxFailures,
            Duration lockDuration) {
        return executeQuery(ds -> {
            String countSql = "INSERT INTO user_login_failures AS existing " +
                    "(principal, login_name, failure_count, last_failure_at, locked_until) " +
                    "VALUES (?, ?, 1, ?, NULL) " +
                    "ON CONFLICT (principal) DO UPDATE SET " +
                    "failure_count = CASE " +
                    "WHEN existing.locked_until IS NULL THEN existing.failure_count + 1 " +
                    "WHEN existing.locked_until > EXCLUDED.last_failure_at THEN existing.failure_count " +
                    "ELSE 1 END, " +
                    "login_name = EXCLUDED.login_name, " +
                    "last_failure_at = EXCLUDED.last_failure_at, " +
                    "locked_until = CASE " +
                    "WHEN existing.locked_until > EXCLUDED.last_failure_at THEN existing.locked_until " +
                    "ELSE NULL END " +
                    "RETURNING failure_count, locked_until";
            // Applied on its own so that two attempts reaching the threshold together agree on when
            // the lock lifts instead of the later one pushing it out.
            String lockSql = "UPDATE user_login_failures SET locked_until = COALESCE(locked_until, ?) " +
                    "WHERE principal = ? RETURNING failure_count, locked_until";
            try (Connection connection = ds.getConnection()) {
                LoginFailureRecord counted;
                try (PreparedStatement ps = connection.prepareStatement(countSql)) {
                    ps.setString(1, principal);
                    ps.setString(2, loginName);
                    ps.setTimestamp(3, Timestamp.from(now));
                    try (ResultSet rs = ps.executeQuery()) {
                        if (!rs.next()) {
                            throw new SQLException("Counting the failed login of " + principal +
                                    " returned no row");
                        }
                        counted = loginFailureRecordOf(rs);
                    }
                }
                if (counted.isLocked() || counted.getFailureCount() < maxFailures) {
                    return counted;
                }
                try (PreparedStatement ps = connection.prepareStatement(lockSql)) {
                    ps.setTimestamp(1, Timestamp.from(now.plus(lockDuration)));
                    ps.setString(2, principal);
                    try (ResultSet rs = ps.executeQuery()) {
                        return rs.next() ? loginFailureRecordOf(rs) : counted;
                    }
                }
            }
        }, "Unable to record the failed login of " + principal);
    }

    /**
     * Releases the account's lock if its period has run out.
     *
     * <p>One statement decides and acts, so that of everything looking at this lock - a login
     * arriving now, and the engine's own sweep of expired locks - exactly one is told it released
     * it, and the release is therefore announced once.</p>
     *
     * @return true when this call released a lock that had run out
     */
    public boolean releaseExpiredLock(String principal, Instant now) {
        return executeQuery(ds -> {
            String sql = "DELETE FROM user_login_failures WHERE principal = ? " +
                    "AND locked_until IS NOT NULL AND locked_until <= ? RETURNING principal";
            try (
                    Connection connection = ds.getConnection();
                    PreparedStatement ps = connection.prepareStatement(sql)) {
                ps.setString(1, principal);
                ps.setTimestamp(2, Timestamp.from(now));
                try (ResultSet rs = ps.executeQuery()) {
                    return rs.next();
                }
            }
        }, "Unable to release the expired lock of " + principal);
    }

    /**
     * Forgets what has been counted against the account, which is what a successful login, an
     * expired lock, and an administrator lifting the lock all amount to.
     */
    public void clearLoginFailures(String principal) {
        executeQuery(ds -> {
            String sql = "DELETE FROM user_login_failures WHERE principal = ?";
            try (
                    Connection connection = ds.getConnection();
                    PreparedStatement ps = connection.prepareStatement(sql)) {
                ps.setString(1, principal);
                ps.executeUpdate();
            }
            return null;
        }, "Unable to clear the login failures of " + principal);
    }

    private static LoginFailureRecord loginFailureRecordOf(ResultSet rs) throws SQLException {
        Timestamp lockedUntil = rs.getTimestamp("locked_until");
        return new LoginFailureRecord(
                rs.getInt("failure_count"),
                lockedUntil == null ? null : lockedUntil.toInstant());
    }

    public Map<String, List<String>> getAllSsoScopeDependencies() {
        return executeQuery(ds -> {
            Map<String, List<String>> map = new HashMap<>();
            String sql = "SELECT scope, dependencies FROM sso_scope_dependency";
            try (
                    Connection connection = ds.getConnection();
                    PreparedStatement ps = connection.prepareStatement(sql)) {
                try (ResultSet rs = ps.executeQuery()) {
                    while (rs.next()) {
                        map.put(rs.getString("scope"), SsoService.scopeAsList(rs.getString("dependencies")));
                    }
                }
            }
            return map;
        }, "Unable to initialize scope dependencies");
    }

    private <T> T executeQuery(ThrowingFunction<DataSource, T, SQLException> resultMapper, String errMsg) {
        DataSource ds;

        try {
            ds = (DataSource) new InitialContext().lookup(DATA_SOURCE);
            if (ds == null) {
                throw new RuntimeException("Failed to obtain data source");
            }
            return resultMapper.apply(ds);
        } catch (SQLException ex) {
            throw new RuntimeException("Database query failed", ex);
        } catch (NamingException ex) {
            throw new RuntimeException("Error looking up resource " + DATA_SOURCE, ex);
        } catch (Exception ex) {
            throw new RuntimeException(errMsg, ex);
        }
    }

    @FunctionalInterface
    private interface ThrowingFunction<T, R, E extends Exception> {
        R apply(T t) throws E;
    }

    private enum ClientInfoMapper implements Function<ResultSet, ClientInfo> {
        INSTANCE;

        public static class ClientInfoMappingException extends RuntimeException {
            public ClientInfoMappingException(SQLException cause) {
                super(cause);
            }
        }

        @Override
        public ClientInfo apply(ResultSet rs) {
            try {
                return new ClientInfo().withClientId(rs.getString("client_id"))
                        .withClientSecret(rs.getString("client_secret"))
                        .withCertificateLocation(rs.getString("certificate_location"))
                        .withCallbackPrefix(rs.getString("callback_prefix"))
                        .withEncryptedUserInfo(rs.getBoolean("encrypted_userinfo"))
                        .withClientNotificationCallback(
                                StringUtils.defaultIfEmpty(rs.getString("notification_callback"), ""))
                        .withScope(SsoService.scopeAsList(rs.getString("scope")))
                        .withIsTrusted(rs.getBoolean("trusted"))
                        .withNotificationCallbackProtocol(rs.getString("notification_callback_protocol"))
                        .withNotificationCallbackVerifyHost(rs.getBoolean("notification_callback_verify_host"))
                        .withNotificationCallVerifyChain(rs.getBoolean("notification_callback_verify_chain"));
            } catch (SQLException sqlException) {
                throw new ClientInfoMappingException(sqlException);
            }
        }
    }
}
