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

import javax.validation.Valid;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class BusinessAPICreationModel {
    private String name;
    private String identifier;
    private String description;
    private boolean requiresAuthorization;
    private List<ScopeGetModel> scopes = null;

    /**
     **/
    public BusinessAPICreationModel displayName(String displayName) {

        this.name = displayName;
        return this;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("name")
    @Valid
    public String getName() {
        return name;
    }
    public void setName(String name) {
        this.name = name;
    }

    /**
     **/
    public BusinessAPICreationModel identifier(String identifier) {

        this.identifier = identifier;
        return this;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("identifier")
    @Valid
    public String getIdentifier() {
        return identifier;
    }
    public void setIdentifier(String identifier) {
        this.identifier = identifier;
    }

    /**
     **/
    public BusinessAPICreationModel description(String description) {

        this.description = description;
        return this;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("description")
    @Valid
    public String getDescription() {
        return description;
    }
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     **/
    public BusinessAPICreationModel requiresAuthorization(Boolean requiresAuthorization) {

        this.requiresAuthorization = requiresAuthorization;
        return this;
    }

    @ApiModelProperty(value = "")
    @JsonProperty("requiresAuthorization")
    @Valid
    public Boolean getRequiresAuthorization() {
        return requiresAuthorization;
    }
    public void setRequiresAuthorization(Boolean requiresAuthorization) {
        this.requiresAuthorization = requiresAuthorization;
    }

    /**
     **/
    public BusinessAPICreationModel scopes(List<ScopeGetModel> scopes) {

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

    public BusinessAPICreationModel addScopesItem(ScopeGetModel scopesItem) {
        if (this.scopes == null) {
            this.scopes = new ArrayList<>();
        }
        this.scopes.add(scopesItem);
        return this;
    }

    @Override
    public boolean equals(java.lang.Object o) {

        if (this == o) {
            return true;
        }
        if (o == null || getClass() != o.getClass()) {
            return false;
        }
        BusinessAPICreationModel businessAPICreationModel = (BusinessAPICreationModel) o;
        return Objects.equals(this.name, businessAPICreationModel.name) &&
                Objects.equals(this.description, businessAPICreationModel.description) &&
                Objects.equals(this.identifier, businessAPICreationModel.identifier) &&
                Objects.equals(this.requiresAuthorization, businessAPICreationModel.requiresAuthorization) &&
                Objects.equals(this.scopes, businessAPICreationModel.scopes);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, description, identifier, requiresAuthorization, scopes);
    }

    @Override
    public String toString() {

        StringBuilder sb = new StringBuilder();
        sb.append("class BusinessAPICreationModel {\n");

        sb.append("    displayName: ").append(toIndentedString(name)).append("\n");
        sb.append("    description: ").append(toIndentedString(description)).append("\n");
        sb.append("    identifier: ").append(toIndentedString(identifier)).append("\n");
        sb.append("    requiresAuthorization: ").append(toIndentedString(requiresAuthorization)).append("\n");
        sb.append("    scopes: ").append(toIndentedString(scopes)).append("\n");
        sb.append("}");
        return sb.toString();
    }

    /**
     * Convert the given object to string with each line indented by 4 spaces
     * (except the first line).
     */
    private String toIndentedString(java.lang.Object o) {

        if (o == null) {
            return "null";
        }
        return o.toString().replace("\n", "\n");
    }
}
