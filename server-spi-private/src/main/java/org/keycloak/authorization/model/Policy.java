/*
 * JBoss, Home of Professional Open Source.
 * Copyright 2016 Red Hat, Inc., and individual contributors
 * as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.authorization.model;

import org.keycloak.representations.idm.authorization.DecisionStrategy;
import org.keycloak.representations.idm.authorization.Logic;
import org.keycloak.storage.SearchableModelField;

import java.util.Map;
import java.util.Set;

/**
 * Represents an authorization policy and all the configuration associated with it.
 *
 * @author <a href="mailto:psilva@redhat.com">Pedro Igor</a>
 */
public interface Policy {

    public static class SearchableFields {
        public static final SearchableModelField<Policy> ID = new SearchableModelField<>("id", String.class);
        public static final SearchableModelField<Policy> NAME = new SearchableModelField<>("name", String.class);
        public static final SearchableModelField<Policy> RESOURCE_SERVER_ID = new SearchableModelField<>("resourceServerId", String.class);
        public static final SearchableModelField<Policy> RESOURCE_ID = new SearchableModelField<>("resourceId", String.class);
        public static final SearchableModelField<Policy> SCOPE_ID = new SearchableModelField<>("scopeId", String.class);
        public static final SearchableModelField<Policy> TYPE = new SearchableModelField<>("type", String.class);
        public static final SearchableModelField<Policy> OWNER = new SearchableModelField<>("owner", String.class);
        public static final SearchableModelField<Policy> CONFIG = new SearchableModelField<>("config", String.class);
        public static final SearchableModelField<Policy> ASSOCIATED_POLICY_ID = new SearchableModelField<>("associatedPolicyId", String.class);
        public static final SearchableModelField<Policy> REALM_ID = new SearchableModelField<>("realmId", String.class);
    }

    public static enum FilterOption {
        ID("id", SearchableFields.ID),
        PERMISSION("permission", SearchableFields.TYPE),
        OWNER("owner", SearchableFields.OWNER),
        ANY_OWNER("owner.any", SearchableFields.OWNER),
        RESOURCE_ID("resources.id", SearchableFields.RESOURCE_ID),
        SCOPE_ID("scopes.id", SearchableFields.SCOPE_ID),
        CONFIG("config", SearchableFields.CONFIG),
        TYPE("type", SearchableFields.TYPE),
        NAME("name", SearchableFields.NAME);

        public static final String[] EMPTY_FILTER = new String[0];
        private final String name;
        private final SearchableModelField<Policy> searchableModelField;

        FilterOption(String name, SearchableModelField<Policy> searchableModelField) {
            this.name = name;
            this.searchableModelField = searchableModelField;
        }


        public String getName() {
            return name;
        }

        public SearchableModelField<Policy> getSearchableModelField() {
            return searchableModelField;
        }
    }
    
    public static final String CONFIG_SEPARATOR = "##";

    /**
     * Returns the unique identifier for this instance.
     *
     * @return the unique identifier for this instance
     */
    String getId();

    /**
     * Returns the type of this policy.
     *
     * @return the type of this policy
     */
    String getType();

    /**
     * Returns the {@link DecisionStrategy} for this policy.
     *
     * @return the decision strategy defined for this policy
     */
    DecisionStrategy getDecisionStrategy();

    /**
     * Sets the {DecisionStrategy} for this policy.
     *
     * @param decisionStrategy for this policy
     */
    void setDecisionStrategy(DecisionStrategy decisionStrategy);

    /**
     * Returns the {@link Logic} for this policy.
     *
     * @return the decision strategy defined for this policy
     */
    Logic getLogic();

    /**
     * Sets the {Logic} for this policy.
     *
     * @param logic for this policy
     */
    void setLogic(Logic logic);

    /**
     * Returns a {@link Map} holding string-based key/value pairs representing any additional configuration for this policy.
     *
     * @return a unmodifiable map with any additional configuration defined for this policy.
     */
    Map<String, String> getConfig();


    /**
     * Sets a {@link Map} with string-based key/value pairs representing any additional configuration for this policy.
     *
     * @param config a map with any additional configuration for this policy.
     */
    void setConfig(Map<String, String> config);

    void removeConfig(String name);
    void putConfig(String name, String value);

    /**
     * Returns the name of this policy.
     *
     * @return the name of this policy
     */
    String getName();

    /**
     * Sets an unique name to this policy.
     *
     * @param name an unique name
     */
    void setName(String name);

    /**
     * Returns the description of this policy.
     *
     * @return a description or null of there is no description
     */
    String getDescription();

    /**
     * Sets the description for this policy.
     *
     * @param description a description
     */
    void setDescription(String description);

    /**
     * Returns the {@link ResourceServer} where this policy belongs to.
     *
     * @return a resource server
     */
     ResourceServer getResourceServer();

    /**
     * Returns the {@link Policy} instances associated with this policy and used to evaluate authorization decisions when
     * this policy applies.
     *
     * @return the associated policies or an empty set if no policy is associated with this policy
     */
    Set<Policy> getAssociatedPolicies();

    /**
     * Returns the {@link Resource} instances where this policy applies.
     *
     * @return a set with all resource instances where this policy applies. Or an empty set if there is no resource associated with this policy
     */
    Set<Resource> getResources();

    /**
     * Returns the {@link Scope} instances where this policy applies.
     *
     * @return a set with all scope instances where this policy applies. Or an empty set if there is no scope associated with this policy
     */
    Set<Scope> getScopes();

    String getOwner();

    void setOwner(String owner);

    void addScope(Scope scope);

    void removeScope(Scope scope);

    void addAssociatedPolicy(Policy associatedPolicy);

    void removeAssociatedPolicy(Policy associatedPolicy);

    void addResource(Resource resource);

    void removeResource(Resource resource);
}
