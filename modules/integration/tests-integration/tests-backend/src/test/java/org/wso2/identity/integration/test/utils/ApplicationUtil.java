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

package org.wso2.identity.integration.test.utils;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.json.JSONException;
import org.wso2.carbon.automation.engine.context.TestUserMode;
import org.wso2.carbon.identity.application.common.model.xsd.AssociatedRolesConfig;
import org.wso2.carbon.identity.application.common.model.xsd.ServiceProvider;
import org.wso2.carbon.identity.oauth.stub.dto.OAuthConsumerAppDTO;
import org.wso2.identity.integration.test.oauth2.OAuth2ServiceAbstractIntegrationTest;
import org.wso2.identity.integration.test.rest.api.server.api.resource.v1.model.ScopeGetModel;
import org.wso2.identity.integration.test.rest.api.server.application.management.v1.model.AuthorizedAPICreationModel;
import org.wso2.identity.integration.test.rest.api.server.application.management.v1.model.BusinessAPICreationModel;
import org.wso2.identity.integration.test.rest.api.server.roles.v2.model.Audience;
import org.wso2.identity.integration.test.rest.api.server.roles.v2.model.Permission;
import org.wso2.identity.integration.test.rest.api.server.roles.v2.model.RoleV2;
import org.wso2.identity.integration.test.rest.api.user.common.model.*;
import org.wso2.identity.integration.test.restclients.SCIM2RestClient;

import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ApplicationUtil extends OAuth2ServiceAbstractIntegrationTest {
    private static final String JWT = "JWT";
    private static final String RBAC = "RBAC";
    private static final String SCIM2_USERS_API = "/o/scim2/Users";
    private static final String ACTIONS_API = "/api/server/v1/actions";
    private static final String APPLICATION_MANAGEMENT_API = "/api/server/v1/applications";
    private static final String API_RESOURCE_MANAGEMENT_API = "/api/server/v1/api-resources";
    private static final String INTERNAL_ACTION_MANAGEMENT_VIEW = "internal_action_mgt_view";
    private static final String INTERNAL_ACTION_MANAGEMENT_CREATE = "internal_action_mgt_create";
    private static final String INTERNAL_ACTION_MANAGEMENT_UPDATE = "internal_action_mgt_update";
    private static final String INTERNAL_ACTION_MANAGEMENT_DELETE = "internal_action_mgt_delete";
    private static final String INTERNAL_ORG_USER_MANAGEMENT_LIST = "internal_org_user_mgt_list";
    private static final String INTERNAL_ORG_USER_MANAGEMENT_VIEW = "internal_org_user_mgt_view";
    private static final String INTERNAL_ORG_USER_MANAGEMENT_CREATE = "internal_org_user_mgt_create";
    private static final String INTERNAL_ORG_USER_MANAGEMENT_UPDATE = "internal_org_user_mgt_update";
    private static final String INTERNAL_ORG_USER_MANAGEMENT_DELETE = "internal_org_user_mgt_delete";
    private static final String INTERNAL_APPLICATION_MANAGEMENT_VIEW = "internal_application_mgt_view";
    private static final String INTERNAL_APPLICATION_MANAGEMENT_UPDATE = "internal_application_mgt_update";
    private static final String INTERNAL_API_RESOURCE_VIEW = "internal_api_resource_view";
    private static final String INTERNAL_API_RESOURCE_CREATE = "internal_api_resource_create";
    private static final String CUSTOM_SCOPE_1 = "test_custom_scope_1";
    private static final String CUSTOM_SCOPE_2 = "test_custom_scope_2";
    private static final String CUSTOM_SCOPE_3 = "test_custom_scope_3";
    private static final String TEST_ROLE_APPLICATION = "test_role_application";
    private static final String USERS = "users";
    private static final String TEST_USER = "test_user";
    private static final String ADMIN_WSO2 = "Admin@wso2";
    private static final String TEST_USER_GIVEN_NAME = "test_user_given";
    private static final String TEST_USER_GMAIL_COM = "test.user@gmail.com";
    private static final Boolean REQUIRES_AUTHORIZATION = true;

    private List<String> customScopes = new ArrayList<>();
    private List<String> systemAPIsToAuthorize = new ArrayList<>();
    private List<Permission> permissions = new ArrayList<>();

    protected SCIM2RestClient scim2RestClient;

    protected void init(TestUserMode userMode) throws Exception {

        super.init(userMode);
        scim2RestClient = new SCIM2RestClient(serverURL, tenantInfo);

        populateData();

    }
    public void createApplicationWithExtServiceIntegration(TestUserMode userMode, String externalServiceName, String externalServiceURI, String audience, String applicationGrantType) throws Exception {
        this.init(userMode);

        // creates application
        String applicationId = registerApplication(applicationGrantType, audience);
        authorizeSystemAndBusinessAPIs(applicationId, externalServiceName, externalServiceURI, systemAPIsToAuthorize, customScopes);

        // creates users and roles
        String roleID = createRole(TEST_ROLE_APPLICATION, applicationId, audience, permissions);
        String userID = createUser(TEST_USER, ADMIN_WSO2, TEST_USER_GIVEN_NAME, TEST_USER_GMAIL_COM);
        assignRoleToUser(roleID, userID);
    }

    private String registerApplication(String grantType, String audience) {
        OAuthConsumerAppDTO applicationDTO = getBasicOAuthApp(OAuth2Constant.CALLBACK_URL);
        applicationDTO.setTokenType(JWT);

        switch (grantType) {
            case "password":
                applicationDTO.setGrantTypes(OAuth2Constant.OAUTH2_GRANT_TYPE_RESOURCE_OWNER);
        }

        AssociatedRolesConfig associatedRolesConfig = new AssociatedRolesConfig();
        associatedRolesConfig.setAllowedAudience(audience);

        ServiceProvider serviceProvider;
        try {
            serviceProvider = registerApplicationAudienceServiceProvider(applicationDTO, associatedRolesConfig);
        } catch (Exception e) {
            throw new RuntimeException("Error occurred while registering service provider: " + applicationDTO.getApplicationName());
        }

        return serviceProvider.getApplicationResourceId();
    }

    /**
     * Authorizes system APIs and business APIs.
     *
     * @param applicationId Application id.
     * @param customScopes
     * @throws Exception
     */
    private void authorizeSystemAndBusinessAPIs(String applicationId, String externalServiceName, String externalServiceURI, List<String> systemAPIs, List<String> customScopes) throws Exception {
        // authorizes system APIs
        if (!CarbonUtils.isLegacyAuthzRuntimeEnabled()) {
            authorizeSystemAPIs(applicationId, systemAPIs);
        }

        //  creates business API
        BusinessAPICreationModel businessAPICreationModel = new BusinessAPICreationModel();
        businessAPICreationModel.setName(externalServiceName);
        businessAPICreationModel.setIdentifier(externalServiceURI);
        businessAPICreationModel.setDescription("This is a test external service");
        businessAPICreationModel.setRequiresAuthorization(REQUIRES_AUTHORIZATION);

        List<ScopeGetModel> customScopesToAdd = new ArrayList<>();
        customScopes.forEach(scope -> {
            ScopeGetModel newCustomScope = new ScopeGetModel();
            newCustomScope.setName(scope);
            newCustomScope.setDescription("This is a test custom scope");
            newCustomScope.setDisplayName(scope);

            customScopesToAdd.add(newCustomScope);
        });

        businessAPICreationModel.setScopes(customScopesToAdd);
        String businessApiId = createBusinessAPIs(businessAPICreationModel);

        // authorizes business APIs
        AuthorizedAPICreationModel authorizedBusinessAPICreationModel = new AuthorizedAPICreationModel();
        authorizedBusinessAPICreationModel.setId(businessApiId);
        authorizedBusinessAPICreationModel.setPolicyIdentifier(RBAC);
        authorizedBusinessAPICreationModel.setScopes(customScopes);
        authorizeBusinessAPIs(applicationId, authorizedBusinessAPICreationModel);
    }

    private String createRole(String roleName, String applicationId, String audience, List<Permission> permissions) throws JSONException, IOException {
        Audience roleAudience = new Audience(audience, applicationId);
        RoleV2 role = new RoleV2(roleAudience, roleName, permissions, Collections.emptyList());

        return addRole(role);
    }

    private String createUser(String username, String password, String givenName, String email) throws Exception {
        UserObject userInfo = new UserObject();
        userInfo.setUserName(username);
        userInfo.setPassword(password);
        userInfo.setName(new Name().givenName(givenName));
        userInfo.addEmail(new Email().value(email));
        return scim2RestClient.createUser(userInfo);
    }

    private void assignRoleToUser(String roleID, String userID) throws IOException {
        RoleItemAddGroupobj rolePatchReqObject = new RoleItemAddGroupobj();
        rolePatchReqObject.setOp(RoleItemAddGroupobj.OpEnum.ADD);
        rolePatchReqObject.setPath(USERS);
        rolePatchReqObject.addValue(new ListObject().value(userID));
        scim2RestClient.updateUserRole(new PatchOperationRequestObject().addOperations(rolePatchReqObject), roleID);
    }

    private void populateData() {
        // creates custom scopes related to the business API
        customScopes.add(CUSTOM_SCOPE_1);
        customScopes.add(CUSTOM_SCOPE_2);
        customScopes.add(CUSTOM_SCOPE_3);

        systemAPIsToAuthorize.add(SCIM2_USERS_API);
        systemAPIsToAuthorize.add(ACTIONS_API);
        systemAPIsToAuthorize.add(APPLICATION_MANAGEMENT_API);
        systemAPIsToAuthorize.add(API_RESOURCE_MANAGEMENT_API);

        permissions.add(new Permission(INTERNAL_ACTION_MANAGEMENT_VIEW));
        permissions.add(new Permission(INTERNAL_ACTION_MANAGEMENT_CREATE));
        permissions.add(new Permission(INTERNAL_ACTION_MANAGEMENT_UPDATE));
        permissions.add(new Permission(INTERNAL_ACTION_MANAGEMENT_DELETE));

        permissions.add(new Permission(INTERNAL_ORG_USER_MANAGEMENT_LIST));
        permissions.add(new Permission(INTERNAL_ORG_USER_MANAGEMENT_VIEW));
        permissions.add(new Permission(INTERNAL_ORG_USER_MANAGEMENT_CREATE));
        permissions.add(new Permission(INTERNAL_ORG_USER_MANAGEMENT_UPDATE));
        permissions.add(new Permission(INTERNAL_ORG_USER_MANAGEMENT_DELETE));

        permissions.add(new Permission(INTERNAL_APPLICATION_MANAGEMENT_VIEW));
        permissions.add(new Permission(INTERNAL_APPLICATION_MANAGEMENT_UPDATE));

        permissions.add(new Permission(INTERNAL_API_RESOURCE_VIEW));
        permissions.add(new Permission(INTERNAL_API_RESOURCE_CREATE));

        customScopes.forEach(permission -> {
            permissions.add(new Permission(permission));
        });
    }

    public String getAccessToken() throws Exception {
        String tenantedTokenURI = getTenantQualifiedURL(OAuth2Constant.ACCESS_TOKEN_ENDPOINT, tenantInfo.getDomain());

        return requestAccessToken(consumerKey, consumerSecret, tenantedTokenURI, TEST_USER, ADMIN_WSO2, permissions);
    }

    public String getAccessToken(List<Permission> additionalPermissions) throws Exception {
        String tenantedTokenURI = getTenantQualifiedURL(OAuth2Constant.ACCESS_TOKEN_ENDPOINT, tenantInfo.getDomain());

        permissions.addAll(additionalPermissions);

        return requestAccessToken(consumerKey, consumerSecret, tenantedTokenURI, TEST_USER, ADMIN_WSO2, permissions);
    }

    public JWTClaimsSet extractJwtClaims(String jwt) throws ParseException {

        SignedJWT signedJWT = SignedJWT.parse(jwt);
        return signedJWT.getJWTClaimsSet();
    }
}
