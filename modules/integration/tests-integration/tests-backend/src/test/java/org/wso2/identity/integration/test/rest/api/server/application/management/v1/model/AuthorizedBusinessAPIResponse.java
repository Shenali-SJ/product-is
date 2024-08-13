/*
 * Copyright (c) 2024, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.identity.integration.test.rest.api.server.application.management.v1.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.annotations.ApiModelProperty;
import org.wso2.identity.integration.test.rest.api.server.api.resource.v1.model.ScopeGetModel;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import javax.validation.Valid;

public class AuthorizedBusinessAPIResponse {
    private String id;
    private String name;
    private String description;
    private String identifier;
    private String type;
    private boolean requiresAuthorization;
    private List<ScopeGetModel> scopes = null;
    private List<String> properties = null;

    /**
     * Set the ID of the API.
     **/
    public AuthorizedBusinessAPIResponse id(String id) {
        this.id = id;
        return this;
    }

    @ApiModelProperty(example = "8925afb3-c970-43fd-84f4-2ceb8f77659b", value = "")
    @JsonProperty("id")
    @Valid
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    /**
     * Set the name of the API.
     **/
    public AuthorizedBusinessAPIResponse name(String name) {
        this.name = name;
        return this;
    }

    @ApiModelProperty(example = "", value = "")
    @JsonProperty("name")
    @Valid
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    /**
     * Set the description of the API.
     **/
    public AuthorizedBusinessAPIResponse description(String description) {
        this.description = description;
        return this;
    }

    @ApiModelProperty(example = "", value = "")
    @JsonProperty("description")
    @Valid
    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * Set the identifier of the API.
     **/
    public AuthorizedBusinessAPIResponse identifier(String identifier) {
        this.identifier = identifier;
        return this;
    }

    @ApiModelProperty(example = "", value = "L")
    @JsonProperty("identifier")
    @Valid
    public String getIdentifier() {
        return identifier;
    }

    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    /**
     * Set the type of the API.
     **/
    public AuthorizedBusinessAPIResponse type(String type) {
        this.type = type;
        return this;
    }

    @ApiModelProperty(example = "BUSINESS", value = "")
    @JsonProperty("type")
    @Valid
    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    /**
     * Set whether the API requires authorization.
     **/
    public AuthorizedBusinessAPIResponse requiresAuthorization(boolean requiresAuthorization) {
        this.requiresAuthorization = requiresAuthorization;
        return this;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("requiresAuthorization")
    public boolean isRequiresAuthorization() {
        return requiresAuthorization;
    }

    public void setRequiresAuthorization(boolean requiresAuthorization) {
        this.requiresAuthorization = requiresAuthorization;
    }

    /**
     * Set the list of scopes for the API.
     **/
    public AuthorizedBusinessAPIResponse scopes(List<ScopeGetModel> scopes) {
        this.scopes = scopes;
        return this;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("scopes")
    @Valid
    public List<ScopeGetModel> getScopes() {
        return scopes;
    }

    public void setScopes(List<ScopeGetModel> scopes) {
        this.scopes = scopes;
    }

    public AuthorizedBusinessAPIResponse addScopesItem(ScopeGetModel scopeItem) {
        if (this.scopes == null) {
            this.scopes = new ArrayList<>();
        }
        this.scopes.add(scopeItem);
        return this;
    }

    /**
     * Set the list of properties for the API.
     **/
    public AuthorizedBusinessAPIResponse properties(List<String> properties) {
        this.properties = properties;
        return this;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("properties")
    @Valid
    public List<String> getProperties() {
        return properties;
    }

    public void setProperties(List<String> properties) {
        this.properties = properties;
    }

    public AuthorizedBusinessAPIResponse addPropertiesItem(String propertyItem) {
        if (this.properties == null) {
            this.properties = new ArrayList<>();
        }
        this.properties.add(propertyItem);
        return this;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        AuthorizedBusinessAPIResponse that = (AuthorizedBusinessAPIResponse) o;
        return requiresAuthorization == that.requiresAuthorization &&
                Objects.equals(id, that.id) &&
                Objects.equals(name, that.name) &&
                Objects.equals(description, that.description) &&
                Objects.equals(identifier, that.identifier) &&
                Objects.equals(type, that.type) &&
                Objects.equals(scopes, that.scopes) &&
                Objects.equals(properties, that.properties);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, name, description, identifier, type, requiresAuthorization, scopes, properties);
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("class APIRepresentation {\n");

        sb.append("    id: ").append(toIndentedString(id)).append("\n");
        sb.append("    name: ").append(toIndentedString(name)).append("\n");
        sb.append("    description: ").append(toIndentedString(description)).append("\n");
        sb.append("    identifier: ").append(toIndentedString(identifier)).append("\n");
        sb.append("    type: ").append(toIndentedString(type)).append("\n");
        sb.append("    requiresAuthorization: ").append(toIndentedString(requiresAuthorization)).append("\n");
        sb.append("    scopes: ").append(toIndentedString(scopes)).append("\n");
        sb.append("    properties: ").append(toIndentedString(properties)).append("\n");
        sb.append("}");
        return sb.toString();
    }

    private String toIndentedString(Object o) {
        if (o == null) {
            return "null";
        }
        return o.toString().replace("\n", "\n    ");
    }
}
