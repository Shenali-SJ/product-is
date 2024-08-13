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

package org.wso2.identity.integration.test.actions;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.lang.ArrayUtils;
import org.apache.http.HttpStatus;
import org.json.JSONException;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;
import org.wso2.carbon.automation.engine.context.TestUserMode;
import org.wso2.carbon.identity.application.common.model.xsd.AssociatedRolesConfig;
import org.wso2.carbon.identity.application.common.model.xsd.ServiceProvider;
import org.wso2.carbon.identity.oauth.stub.dto.OAuthConsumerAppDTO;
import org.wso2.identity.integration.common.clients.oauth.OauthAdminClient;
import org.wso2.identity.integration.test.oauth2.OAuth2ServiceAbstractIntegrationTest;
import org.wso2.identity.integration.test.rest.api.server.action.management.v1.model.AuthenticationType;
import org.wso2.identity.integration.test.rest.api.server.action.management.v1.model.Endpoint;
import org.wso2.identity.integration.test.rest.api.server.api.resource.v1.model.ScopeGetModel;
import org.wso2.identity.integration.test.rest.api.server.application.management.v1.model.AuthorizedAPICreationModel;
import org.wso2.identity.integration.test.rest.api.server.application.management.v1.model.BusinessAPICreationModel;
import org.wso2.identity.integration.test.rest.api.server.roles.v2.model.Audience;
import org.wso2.identity.integration.test.rest.api.server.roles.v2.model.Permission;
import org.wso2.identity.integration.test.rest.api.server.roles.v2.model.RoleV2;
import org.wso2.identity.integration.test.rest.api.user.common.model.*;
import org.wso2.identity.integration.test.restclients.ActionsRestClient;
import org.wso2.identity.integration.test.restclients.SCIM2RestClient;
import org.wso2.identity.integration.test.utils.CarbonUtils;
import org.wso2.identity.integration.test.utils.OAuth2Constant;

import java.io.IOException;
import java.text.ParseException;
import java.util.*;

public class PreIssueAccessTokenWithTestCase extends ActionsBaseTestCase {
    private class OAuth2ServiceHelper extends OAuth2ServiceAbstractIntegrationTest {
        public OAuth2ServiceHelper() throws Exception {
            super.init(TestUserMode.TENANT_USER);

            setSystemproperties();
        }

        public String getConsumerKey() {
            return super.consumerKey;
        }

        public String getConsumerSecret() {
            return super.consumerSecret;
        }
    }
    private static final String JWT = "JWT";
    private static final String RBAC = "RBAC";
    private static final String USERS = "users";
    private static final String TEST_USER = "test_user";
    private static final String ADMIN_WSO2 = "Admin@wso2";
    private static final String USERNAME_PROPERTY = "username";
    private static final String PASSWORD_PROPERTY = "password";
    private static final String TEST_USER_GIVEN = "test_user_given";
    private static final String TEST_USER_GMAIL_COM = "test.user@gmail.com";
    private static final String APPLICATION_AUDIENCE = "APPLICATION";
    private static final String TEST_ROLE_APPLICATION = "test_role_application";
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
    private static final String SCIM2_USERS_API = "/o/scim2/Users";
    private static final String ACTIONS_API = "/api/server/v1/actions";
    private static final String APPLICATION_MANAGEMENT_API = "/api/server/v1/applications";
    private static final String API_RESOURCE_MANAGEMENT_API = "/api/server/v1/api-resources";
    private final static Boolean REQUIRES_AUTHORIZATION = true;
    protected OAuth2ServiceHelper oAuth2Service;

    protected SCIM2RestClient scim2RestClient;
    private String roleID;
    private String userID;
    private String appId;

    private String consumerKeyStr;
    private String consumerSecretStr;
    private String accessToken;

    private String[] customScopesFromToken;

    private List<String> consumerKeys = new ArrayList<>();
    private List<String> consumerSecrets = new ArrayList<>();
    private List<String> customScopes = new ArrayList<>();
    private List<Permission> userPermissions = new ArrayList<>();
    @BeforeClass(alwaysRun = true)
    public void testInit() throws Exception {

        super.init(TestUserMode.TENANT_USER);

        oAuth2Service = this.new OAuth2ServiceHelper();

        restClient = new ActionsRestClient(serverURL, tenantInfo);
        scim2RestClient = new SCIM2RestClient(serverURL, tenantInfo);
        adminClient = new OauthAdminClient(backendURL, sessionCookie);

        setSystemproperties();
    }

    // TODO: check what is wrong here
//    @AfterClass(alwaysRun = true)
//    public void atEnd() throws Exception {
//        restClient.deleteV2Role(roleID);
//        deleteApp(appId);
//        scim2RestClient.deleteUser(userID);
//        consumerKey = null;
//        consumerSecret = null;
//        appId = null;
//        restClient.closeHttpClient();
//    }

    /**
     * Provides data for testing registration pre-requisites.
     * Each dataset consists of an external service name and its uri.
     *
     * @return Two-dimensional array containing pairs of external service names and its uris.
     */
    @DataProvider(name = "getExternalServiceInfo")
    public Object[][] getExternalServiceInfo() {

        return new Object[][]{
                {"TestExternalService", "https://wso2is.free.beeceptor.com"}
        };
    }

    @Test(groups = "wso2.is", description = "Registers an application with specified audience type, grant type. " +
            "Creates a role, adds users and associates users with roles. Subscribe to necessary API resources.",
            dataProvider = "getExternalServiceInfo")
    private void testRegisterPreRequisites(String externalServiceName, String externalServiceURI) throws Exception {
        appId = registerApplication(externalServiceName, externalServiceURI);
        roleID = createRoles(appId);
        userID = createUser();
        assignRoleToUser(roleID, userID);
    }

    private String registerApplication(String externalServiceName, String externalServiceURI) throws Exception {
        OAuthConsumerAppDTO applicationDTO = oAuth2Service.getBasicOAuthApp(OAuth2Constant.CALLBACK_URL);
        applicationDTO.setTokenType(JWT);
        applicationDTO.setGrantTypes(OAuth2Constant.OAUTH2_GRANT_TYPE_RESOURCE_OWNER);

        AssociatedRolesConfig associatedRolesConfig = new AssociatedRolesConfig();
        associatedRolesConfig.setAllowedAudience(APPLICATION_AUDIENCE);
        ServiceProvider serviceProvider = null;
        try {
            serviceProvider = oAuth2Service.registerApplicationAudienceServiceProvider(applicationDTO, associatedRolesConfig);
        } catch (Exception e) {
            throw new RuntimeException("Error occurred while creating service provider: " + applicationDTO.getApplicationName());
        }

        applicationDTO = adminClient.getOAuthAppByName(serviceProvider.getApplicationName());
        consumerKeyStr = applicationDTO.getOauthConsumerKey();
        consumerSecretStr = applicationDTO.getOauthConsumerSecret();

        consumerKeys.add(oAuth2Service.getConsumerKey());
        consumerSecrets.add(oAuth2Service.getConsumerSecret());

        String applicationId = serviceProvider.getApplicationResourceId();

        // Adds custom scopes related to the business API
        customScopes.add(CUSTOM_SCOPE_1);
        customScopes.add(CUSTOM_SCOPE_2);
        customScopes.add(CUSTOM_SCOPE_3);

        authorizeAPIs(applicationId, customScopes, externalServiceName, externalServiceURI);

        return applicationId;
    }

    // TODO: add doc comments
    private String createRoles(String appID) throws JSONException, IOException {

        userPermissions.add(new Permission(INTERNAL_ACTION_MANAGEMENT_VIEW));
        userPermissions.add(new Permission(INTERNAL_ACTION_MANAGEMENT_CREATE));
        userPermissions.add(new Permission(INTERNAL_ACTION_MANAGEMENT_UPDATE));
        userPermissions.add(new Permission(INTERNAL_ACTION_MANAGEMENT_DELETE));

        userPermissions.add(new Permission(INTERNAL_ORG_USER_MANAGEMENT_LIST));
        userPermissions.add(new Permission(INTERNAL_ORG_USER_MANAGEMENT_VIEW));
        userPermissions.add(new Permission(INTERNAL_ORG_USER_MANAGEMENT_CREATE));
        userPermissions.add(new Permission(INTERNAL_ORG_USER_MANAGEMENT_UPDATE));
        userPermissions.add(new Permission(INTERNAL_ORG_USER_MANAGEMENT_DELETE));

        userPermissions.add(new Permission(INTERNAL_APPLICATION_MANAGEMENT_VIEW));
        userPermissions.add(new Permission(INTERNAL_APPLICATION_MANAGEMENT_UPDATE));

        userPermissions.add(new Permission(INTERNAL_API_RESOURCE_VIEW));
        userPermissions.add(new Permission(INTERNAL_API_RESOURCE_CREATE));

        for (String customScope : customScopes) {
            userPermissions.add(new Permission(customScope));
        }

        Audience roleAudience = new Audience(APPLICATION_AUDIENCE, appID);
        RoleV2 role = new RoleV2(roleAudience, TEST_ROLE_APPLICATION, userPermissions, Collections.emptyList());

        return oAuth2Service.addRole(role);
    }

    private String createUser() throws Exception {
        UserObject userInfo = new UserObject();
        userInfo.setUserName(TEST_USER);
        userInfo.setPassword(ADMIN_WSO2);
        userInfo.setName(new Name().givenName(TEST_USER_GIVEN));
        userInfo.addEmail(new Email().value(TEST_USER_GMAIL_COM));
        return scim2RestClient.createUser(userInfo);
    }

    private void assignRoleToUser(String roleID, String userID) throws IOException {
        RoleItemAddGroupobj rolePatchReqObject = new RoleItemAddGroupobj();
        rolePatchReqObject.setOp(RoleItemAddGroupobj.OpEnum.ADD);
        rolePatchReqObject.setPath(USERS);
        rolePatchReqObject.addValue(new ListObject().value(userID));
        scim2RestClient.updateUserRole(new PatchOperationRequestObject().addOperations(rolePatchReqObject), roleID);
    }

    /**
     * Authorizes system APIs and business APIs.
     *
     * @param applicationId Application id.
     * @param customScopes
     * @throws Exception
     */
    private void authorizeAPIs(String applicationId, List<String> customScopes, String externalServiceName, String externalServiceURI) throws Exception {
        // Authorizes a few system APIs
        if (!CarbonUtils.isLegacyAuthzRuntimeEnabled()) {
            oAuth2Service.authorizeSystemAPIs(applicationId, new ArrayList<>(Arrays.asList(SCIM2_USERS_API, ACTIONS_API,
                    APPLICATION_MANAGEMENT_API, API_RESOURCE_MANAGEMENT_API)));
        }

        // Creates business API
        BusinessAPICreationModel businessAPICreationModel = new BusinessAPICreationModel();
        businessAPICreationModel.setName(externalServiceName);
        businessAPICreationModel.setIdentifier(externalServiceURI);
        businessAPICreationModel.setDescription("This is a test external service");
        businessAPICreationModel.setRequiresAuthorization(REQUIRES_AUTHORIZATION);
        List<ScopeGetModel> newScopes = new ArrayList<>();
        customScopes.forEach(scope -> {
            ScopeGetModel newCustomScope = new ScopeGetModel();
            newCustomScope.setName(scope);
            newCustomScope.setDescription("This is a test scope");
            newCustomScope.setDisplayName(scope);
            newScopes.add(newCustomScope);
        });
        businessAPICreationModel.setScopes(newScopes);
        String businessAPIID = oAuth2Service.createBusinessAPIs(businessAPICreationModel);

        // Authorizes business APIs
        AuthorizedAPICreationModel authorizedBusinessAPICreationModel = new AuthorizedAPICreationModel();
        authorizedBusinessAPICreationModel.setId(businessAPIID);
        authorizedBusinessAPICreationModel.setPolicyIdentifier(RBAC);
        authorizedBusinessAPICreationModel.setScopes(customScopes);
        oAuth2Service.authorizeBusinessAPIs(applicationId, authorizedBusinessAPICreationModel);
    }

    /**
     * Provides data for creating pre issue access token action
     * Each dataset consists of an endpoint uri and authentication type.
     *
     * @return Two-dimensional array containing pairs of endpoint uris and authentication types.
     */
    @DataProvider(name = "getEndpointDetails")
    public Object[][] getEndpointDetails() {

        return new Object[][]{
                {"https://wso2is.free.beeceptor.com", "Basic"}
        };
    }

    @Test(groups = "wso2.is", description = "Create an action of type PreIssueAccessToken",
            dataProvider = "getEndpointDetails", dependsOnMethods = "testRegisterPreRequisites")
    private void testCreatePreIssueAccessTokenAction(String uri, String authenticationTypeString) {
        Endpoint endpoint = new Endpoint();
        endpoint.setUri(uri);
        AuthenticationType authenticationType = new AuthenticationType();
        switch (authenticationTypeString.toUpperCase()) {
            case "BASIC":
                authenticationType.setType(AuthenticationType.TypeEnum.BASIC);
                Map<String, Object> authProperties = new HashMap<>();
                authProperties.put(USERNAME_PROPERTY, TEST_USER);
                authProperties.put(PASSWORD_PROPERTY, ADMIN_WSO2);
                authenticationType.setProperties(authProperties);
                break;
            default:
                authenticationType.setType(AuthenticationType.TypeEnum.NONE);
        }
        endpoint.setAuthentication(authenticationType);

        int statusCode = createPreIssueAccessToken(endpoint);
        Assert.assertEquals(statusCode, HttpStatus.SC_CREATED);
    }

    private JWTClaimsSet extractJwtClaims(String jwtToken) throws ParseException {

        SignedJWT signedJWT = SignedJWT.parse(jwtToken);
        return signedJWT.getJWTClaimsSet();
    }

    /**
     * Provides consumer keys and secrets for testing purposes.
     * Each dataset consists of a consumer key and its corresponding consumer secret.
     *
     * @return Two-dimensional array containing pairs of consumer keys and secrets.
     */
    @DataProvider(name = "getConsumerKeysAndSecrets")
    public Object[][] getConsumerKeysAndSecrets() {

        Object[][] keysAndSecrets = new Object[consumerKeys.size()][2];
        for (int i = 0; i < consumerKeys.size(); i++) {
            keysAndSecrets[i][0] = consumerKeys.get(i);
            keysAndSecrets[i][1] = consumerSecrets.get(i);
        }
        return keysAndSecrets;
    }

    @Test(groups = "wso2.is", description = "Gets an access token",
            dataProvider = "getConsumerKeysAndSecrets", dependsOnMethods = "testCreatePreIssueAccessTokenAction")
    public void testRequestAccessToken(String consumerKey, String consumerSecret) throws Exception {
        String tenantedTokenURI = getTenantQualifiedURL(OAuth2Constant.ACCESS_TOKEN_ENDPOINT, tenantInfo.getDomain());
        accessToken = oAuth2Service.requestAccessToken(consumerKey, consumerSecret, tenantedTokenURI, TEST_USER, ADMIN_WSO2, userPermissions);
        Assert.assertNotNull(accessToken);
    }

    public String requestAccessToken(String consumerKey, String consumerSecret) throws Exception {
        String tenantedTokenURI = getTenantQualifiedURL(OAuth2Constant.ACCESS_TOKEN_ENDPOINT, tenantInfo.getDomain());
        return oAuth2Service.requestAccessToken(consumerKey, consumerSecret, tenantedTokenURI, TEST_USER, ADMIN_WSO2, userPermissions);
    }

    @DataProvider(name = "getNewCustomScope")
    public Object[][] getNewCustomScope() {
        String[] scopesArray = new String[] {"new_test_custom_scope_1", "new_test_custom_scope_2", "new_test_custom_scope_3"};

        return new Object[][]{
                {"scope", scopesArray},
        };
    }
    @Test(groups = "wso2.is", description = "Check if the added scope is present in the access token",
            dataProvider = "getNewCustomScope", dependsOnMethods = "testRequestAccessToken")
    public void testTokenScopeAddOperation(String scope, String[] newScopeArray) throws Exception {
        JWTClaimsSet jwtClaims = extractJwtClaims(accessToken);

        String scopeString = jwtClaims.getStringClaim(scope);
        String[] scopes = scopeString.split("\\s+");

        for (String str : scopes) {
            System.out.println("Buch 00" + str);
        }

        Assert.assertTrue(ArrayUtils.contains(scopes, newScopeArray[0]));
    }

    @DataProvider(name = "getNewAUDClaim")
    public Object[][] getNewAUDClaim() {

        return new Object[][]{
                {"aud", "zzz1.com"}
        };
    }
    @Test(groups = "wso2.is", description = "Check if the aud claim is present in the access token",
            dataProvider = "getNewAUDClaim", dependsOnMethods = "testRequestAccessToken")
    public void testTokenAudClaimAddOperation(String audClaim, String newAud) throws Exception {
        JWTClaimsSet jwtClaims = extractJwtClaims(accessToken);
        String[] audValueArray = jwtClaims.getStringArrayClaim(audClaim);

        if (audValueArray != null) {
            for (String str : audValueArray) {
                System.out.println("Buch0: " + str);
            }
            Assert.assertTrue(ArrayUtils.contains(audValueArray, newAud));
        } else {
            String audValueString = jwtClaims.getStringClaim(audClaim);
            Assert.assertEquals(audValueString, newAud);
        }
    }

    @DataProvider(name = "getStringClaim")
    public Object[][] getStringClaim() {
        return new Object[][]{
                {"custom_claim_string_1", "testCustomClaim1", 0},
                {"custom_claim_string_2", "testCustomClaim2", 1},
                {"custom_claim_string_3", "testCustomClaim3", 2}
        };
    }

    @Test(groups = "wso2.is", description = "Check if the custom string claim is present in the access token",
            dataProvider = "getStringClaim", dependsOnMethods = "testRequestAccessToken")
    public void testTokenStringClaimAddOperation(String claim, String newClaimValue, int index) throws Exception {
        JWTClaimsSet jwtClaims = extractJwtClaims(accessToken);
        String claimStr = jwtClaims.getStringClaim(claim);
        if (index == 0) {
            Assert.assertEquals(claimStr, newClaimValue);
        }
    }

    @DataProvider(name = "getNumberClaim")
    public Object[][] getNumberClaim() {
        return new Object[][]{
                {"custom_claim_number_1", 78, 0},
                {"custom_claim_number_2", 50, 1},
                {"custom_claim_number_3", 32, 2},
        };
    }

    @Test(groups = "wso2.is", description = "Check if the custom number claim is present in the access token",
            dataProvider = "getNumberClaim", dependsOnMethods = "testRequestAccessToken")
    public void testTokenNumberClaimAddOperation(String claim, Number newClaimValue, int index) throws Exception {
        JWTClaimsSet jwtClaims = extractJwtClaims(accessToken);
        Number claimValue = jwtClaims.getIntegerClaim(claim);
        if (index == 0) {
            Assert.assertEquals(claimValue, newClaimValue);
        }
    }

    @DataProvider(name = "getBooleanClaim")
    public Object[][] getBooleanClaim() {
        return new Object[][]{
                {"custom_claim_boolean_1", true, 0},
                {"custom_claim_boolean_2", false, 1},
                {"custom_claim_boolean_3", true, 2}
        };
    }

    @Test(groups = "wso2.is", description = "Check if the custom boolean claim is present in the access token",
            dataProvider = "getBooleanClaim", dependsOnMethods = "testRequestAccessToken")
    public void testTokenBooleanClaimAddOperation(String claim, Boolean newClaimValue, int index) throws Exception {
        JWTClaimsSet jwtClaims = extractJwtClaims(accessToken);
        Boolean claimValue = jwtClaims.getBooleanClaim(claim);
        if (index == 0) {
            Assert.assertEquals(claimValue, newClaimValue);
        }
    }

    @DataProvider(name = "getStringArrayClaim")
    public Object[][] getStringArrayClaim() {
        String[] claimArray1 = {"TestCustomClaim1", "TestCustomClaim2", "TestCustomClaim3"};
        String[] claimArray2 = {"TestCustomClaim4", "TestCustomClaim5", "TestCustomClaim6"};
        String[] claimArray3 = {"TestCustomClaim7", "TestCustomClaim8", "TestCustomClaim9"};

        return new Object[][]{
                {"custom_claim_string_array_1", claimArray1, 0},
                {"custom_claim_string_array_2", claimArray2, 1},
                {"custom_claim_string_array_3", claimArray3, 2},
        };
    }

    @Test(groups = "wso2.is", description = "Check if the custom string array claim is present in the access token",
            dataProvider = "getStringArrayClaim", dependsOnMethods = "testRequestAccessToken")
    public void testTokenStringArrayClaimAddOperation(String claim, String[] newClaimArray, int index) throws Exception {
        JWTClaimsSet jwtClaims = extractJwtClaims(accessToken);
        String[] claimArray = jwtClaims.getStringArrayClaim(claim);
        if (index == 0) {
            Assert.assertEquals(claimArray, newClaimArray);
        }
    }

    @DataProvider(name = "replaceCustomScope")
    public Object[][] replaceCustomScope() {
        return new Object[][]{
                {"scope", "test_custom_scope_3", "replaced_scope"},
        };
    }
    @Test(groups = "wso2.is", description = "Check if the added scope is present in the access token",
            dataProvider = "replaceCustomScope", dependsOnMethods = "testTokenScopeAddOperation")
    public void testTokenScopeReplaceOperation(String scope, String oldScope, String replacedScope) throws Exception {
        JWTClaimsSet jwtClaims = extractJwtClaims(accessToken);

        String scopeString = jwtClaims.getStringClaim(scope);
        String[] scopes = scopeString.split("\\s+");;
        for (String str : scopes) {
            System.out.println("Buch Rp 1: " + str);
        }
        Assert.assertTrue(ArrayUtils.contains(scopes, replacedScope));
        Assert.assertFalse(ArrayUtils.contains(scopes, oldScope));
    }

    @DataProvider(name = "replaceAUDClaim")
    public Object[][] replaceAUDClaim() {

        return new Object[][]{
                {"aud", consumerKeyStr, "zzz2.com"}
        };
    }
    @Test(groups = "wso2.is", description = "Check if the aud claim is present in the access token",
            dataProvider = "replaceAUDClaim", dependsOnMethods = "testTokenAudClaimAddOperation")
    public void testTokenAudClaimReplaceOperation(String audClaim, String oldAud, String replacedAud) throws Exception {
        JWTClaimsSet jwtClaims = extractJwtClaims(accessToken);
        String[] audValueArray = jwtClaims.getStringArrayClaim(audClaim);

        if (audValueArray != null) {
            for (String str : audValueArray) {
                System.out.println("Buch Rp 2: " + str);
            }
            Assert.assertTrue(ArrayUtils.contains(audValueArray, replacedAud));
            Assert.assertFalse(ArrayUtils.contains(audValueArray, oldAud));
        } else {
            String audValueString = jwtClaims.getStringClaim(audClaim);
            Assert.assertEquals(audValueString, replacedAud);
            Assert.assertNotEquals(audValueString, oldAud);
        }
    }

    @DataProvider(name = "replaceExpiresInClaim")
    public Object[][] replaceExpiresInClaim() {

        return new Object[][]{
                {"expires_in", 7200}
        };
    }
    @Test(groups = "wso2.is", description = "Check if the aud claim is present in the access token",
            dataProvider = "replaceExpiresInClaim", dependsOnMethods = "testRequestAccessToken")
    public void testTokenExpiresInClaimReplaceOperation(String expiresInClaim, long expiresIn) throws Exception {
        JWTClaimsSet jwtClaims = extractJwtClaims(accessToken);

        if (jwtClaims.getClaim(expiresInClaim) != null) {
            Object expValue = jwtClaims.getLongClaim(expiresInClaim);
            Assert.assertEquals(expValue, expiresIn);
        }
    }

    @DataProvider(name = "removeCustomScope")
    public Object[][] removeCustomScope() {
        return new Object[][]{
                {"scope", "test_custom_scope_2"},
        };
    }
    @Test(groups = "wso2.is", description = "Check if the added scope is present in the access token",
            dataProvider = "removeCustomScope", dependsOnMethods = "testTokenScopeReplaceOperation")
    public void testTokenScopeRemoveOperation(String scope, String removedScope) throws Exception {
        JWTClaimsSet jwtClaims = extractJwtClaims(accessToken);

        String scopeString = jwtClaims.getStringClaim(scope);
        String[] scopes = scopeString.split("\\s+");;
        for (String str : scopes) {
            System.out.println("Buch 3" + str);
        }
        Assert.assertFalse(ArrayUtils.contains(scopes, removedScope));
    }

    @DataProvider(name = "removeAUDClaim")
    public Object[][] removeAUDClaim() {

        return new Object[][]{
                {"aud", "zzz1.com"}
        };
    }
    @Test(groups = "wso2.is", description = "Check if the aud claim is present in the access token",
            dataProvider = "removeAUDClaim", dependsOnMethods = "testTokenAudClaimReplaceOperation")
    public void testTokenAudClaimRemoveOperation(String audClaim, String removedAud) throws Exception {
        JWTClaimsSet jwtClaims = extractJwtClaims(accessToken);
        String[] audValueArray = jwtClaims.getStringArrayClaim(audClaim);

        if (audValueArray != null) {
            Assert.assertFalse(ArrayUtils.contains(audValueArray, removedAud));
        } else {
            String audValueString = jwtClaims.getStringClaim(audClaim);
            Assert.assertNotEquals(audValueString, removedAud);
        }
    }
}
