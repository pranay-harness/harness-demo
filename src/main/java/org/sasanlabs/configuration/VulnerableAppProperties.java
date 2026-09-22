package org.sasanlabs.configuration;

import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * This class contains all the properties related to vulnerableApp. This bean is registered through
 * {@link VulnerableAppConfiguration}. In case in future we want to add new properties to
 * vulnerableApp please use this bean.
 *
 * @author KSASAN preetkaran20@gmail.com
 */
public class VulnerableAppProperties {

    /** Contains all the properties present in {@code attackvectors/*.properties} */
    private Properties attackVectorProperties;

    private static final Pattern ENV_VAR_PATTERN = Pattern.compile("\\$\\{([^}]+)\\}");

    public VulnerableAppProperties(Properties attackVectorProperties) {
        super();
        this.attackVectorProperties = attackVectorProperties;
    }

    /**
     * @param propertyKey
     * @return property value by reading {@code attackvectors/*.properties} files.
     *         Environment variables in the format ${VAR_NAME} are resolved from system properties.
     */
    public String getAttackVectorProperty(String propertyKey) {
        String value = attackVectorProperties.getProperty(propertyKey);
        if (value == null) {
            return null;
        }
        return resolveEnvironmentVariables(value);
    }

    /**
     * Resolves environment variable placeholders in the format ${VAR_NAME} by loading from System
     * properties.
     *
     * @param value The string potentially containing environment variable placeholders
     * @return The resolved string with environment variables substituted
     */
    private String resolveEnvironmentVariables(String value) {
        Matcher matcher = ENV_VAR_PATTERN.matcher(value);
        StringBuffer result = new StringBuffer();

        while (matcher.find()) {
            String varName = matcher.group(1);
            String envValue = System.getenv(varName);
            if (envValue == null) {
                envValue = System.getProperty(varName);
            }
            if (envValue != null) {
                matcher.appendReplacement(result, Matcher.quoteReplacement(envValue));
            }
        }
        matcher.appendTail(result);
        return result.toString();
    }
}
