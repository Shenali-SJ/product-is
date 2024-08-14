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
import org.apache.commons.lang.ArrayUtils;
import org.apache.http.HttpStatus;
import org.testng.Assert;
import org.testng.annotations.*;
import org.wso2.carbon.automation.engine.context.TestUserMode;
import org.wso2.identity.integration.test.rest.api.server.action.management.v1.model.ActionModel;
import org.wso2.identity.integration.test.rest.api.server.action.management.v1.model.AuthenticationType;
import org.wso2.identity.integration.test.rest.api.server.action.management.v1.model.Endpoint;
import org.wso2.identity.integration.test.rest.api.server.roles.v2.model.Permission;
import org.wso2.identity.integration.test.utils.ApplicationUtil;

import java.lang.reflect.Method;
import java.util.*;

public class PreIssueAccessTokenTestCase extends ActionsBaseTestCase {
    private static final String USERNAME_PROPERTY = "username";
    private static final String PASSWORD_PROPERTY = "password";
    private static final String TEST_USER = "test_user";
    private static final String ADMIN_WSO2 = "Admin@wso2";
    private static final String EXTERNAL_SERVICE_NAME = "TestExternalService";
    private static final String APPLICATION_AUDIENCE = "APPLICATION";
    private static final String PASSWORD_GRANT_TYPE = "password";
    private static final String EXTERNAL_SERVICE_ENDPOINT = "https://wso2is.free.beeceptor.com";
    private static final String PRE_ISSUE_ACCESS_TOKEN_TYPE = "preIssueAccessToken";
    private static final String ACTION_CREATION_METHOD = "testCreatePreIssueAccessTokenAction";
    private String accessToken;
    private ApplicationUtil applicationUtil;
    @BeforeClass(alwaysRun = true)
    public void testInit() throws Exception {

        TestUserMode userMode = TestUserMode.TENANT_USER;
        super.init(userMode);

        applicationUtil = new ApplicationUtil();
        applicationUtil.createApplicationWithExtServiceIntegration(userMode, EXTERNAL_SERVICE_NAME,
                EXTERNAL_SERVICE_ENDPOINT, APPLICATION_AUDIENCE, PASSWORD_GRANT_TYPE);

        setSystemproperties();
    }

//    @AfterMethod
//    public void tearDown(Method method) throws Exception {
//        String testName = method.getName();
//
//        if (ACTION_CREATION_METHOD.equals(testName)) {
//            accessToken = applicationUtil.getAccessToken();
//        }
//    }

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
     * Provides data for creating pre issue access token action
     * Each dataset consists of an endpoint uri and authentication type.
     *
     * @return Two-dimensional array containing pairs of endpoint uris and authentication types.
     */
    @DataProvider(name = "getEndpointDetails")
    public Object[][] getEndpointDetails() {

        return new Object[][]{
                {EXTERNAL_SERVICE_ENDPOINT, "Basic"}
        };
    }

    @Test(groups = "wso2.is", description = "Create an action of type PreIssueAccessToken",
            dataProvider = "getEndpointDetails")
    private void testCreatePreIssueAccessTokenAction(String uri, String authenticationTypeString) throws Exception {
        ActionModel actionModel = new ActionModel();
        actionModel.setName("Access Token Pre Issue");
        actionModel.setDescription("This is a test pre issue access token type");

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

        Endpoint endpoint = new Endpoint();
        endpoint.setUri(uri);
        endpoint.setAuthentication(authenticationType);

        actionModel.setEndpoint(endpoint);

        int statusCode = createActionType(actionModel, PRE_ISSUE_ACCESS_TOKEN_TYPE);
        Assert.assertEquals(statusCode, HttpStatus.SC_CREATED);
        accessToken = applicationUtil.getAccessToken();
    }

    @DataProvider(name = "getNewCustomScope")
    public Object[][] getNewCustomScope() {
        String[] scopesArray = new String[] {"new_test_custom_scope_1", "new_test_custom_scope_2", "new_test_custom_scope_3"};

        return new Object[][]{
                {"scope", scopesArray},
        };
    }
    @Test(groups = "wso2.is", description = "Check if the added scope is present in the access token",
            dataProvider = "getNewCustomScope", dependsOnMethods = "testCreatePreIssueAccessTokenAction")
    public void testTokenScopeAddOperation(String scope, String[] newScopeArray) throws Exception {
        JWTClaimsSet jwtClaims = applicationUtil.extractJwtClaims(accessToken);

        String scopeString = jwtClaims.getStringClaim(scope);
        String[] scopes = scopeString.split("\\s+");

        Assert.assertTrue(ArrayUtils.contains(scopes, newScopeArray[0]));
    }

    @DataProvider(name = "getNewAUDClaim")
    public Object[][] getNewAUDClaim() {

        return new Object[][]{
                {"aud", "zzz1.com"},
                {"aud", "zzz2.com"},
                {"aud", "zzz3.com"}
        };
    }
    @Test(groups = "wso2.is", description = "Check if the aud claim is present in the access token",
            dataProvider = "getNewAUDClaim", dependsOnMethods = "testCreatePreIssueAccessTokenAction")
    public void testTokenAudClaimAddOperation(String audClaim, String newAud) throws Exception {
        JWTClaimsSet jwtClaims = applicationUtil.extractJwtClaims(accessToken);
        String[] audValueArray = jwtClaims.getStringArrayClaim(audClaim);

        if (audValueArray != null) {
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
            dataProvider = "getStringClaim", dependsOnMethods = "testCreatePreIssueAccessTokenAction")
    public void testTokenStringClaimAddOperation(String claim, String newClaimValue, int index) throws Exception {
        JWTClaimsSet jwtClaims = applicationUtil.extractJwtClaims(accessToken);
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
            dataProvider = "getNumberClaim", dependsOnMethods = "testCreatePreIssueAccessTokenAction")
    public void testTokenNumberClaimAddOperation(String claim, Number newClaimValue, int index) throws Exception {
        JWTClaimsSet jwtClaims = applicationUtil.extractJwtClaims(accessToken);
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
            dataProvider = "getBooleanClaim", dependsOnMethods = "testCreatePreIssueAccessTokenAction")
    public void testTokenBooleanClaimAddOperation(String claim, Boolean newClaimValue, int index) throws Exception {
        JWTClaimsSet jwtClaims = applicationUtil.extractJwtClaims(accessToken);
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
            dataProvider = "getStringArrayClaim", dependsOnMethods = "testCreatePreIssueAccessTokenAction")
    public void testTokenStringArrayClaimAddOperation(String claim, String[] newClaimArray, int index) throws Exception {
        JWTClaimsSet jwtClaims = applicationUtil.extractJwtClaims(accessToken);
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
        JWTClaimsSet jwtClaims = applicationUtil.extractJwtClaims(accessToken);

        String scopeString = jwtClaims.getStringClaim(scope);
        String[] scopes = scopeString.split("\\s+");

        Assert.assertTrue(ArrayUtils.contains(scopes, replacedScope));
        Assert.assertFalse(ArrayUtils.contains(scopes, oldScope));
    }

    @DataProvider(name = "replaceAUDClaim")
    public Object[][] replaceAUDClaim() {
        return new Object[][]{
                {"aud", "zzz3.com", "zzz4.com"}
        };
    }
    @Test(groups = "wso2.is", description = "Check if the aud claim is present in the access token",
            dataProvider = "replaceAUDClaim", dependsOnMethods = "testTokenAudClaimAddOperation")
    public void testTokenAudClaimReplaceOperation(String audClaim, String oldAud, String replacedAud) throws Exception {
        JWTClaimsSet jwtClaims = applicationUtil.extractJwtClaims(accessToken);
        String[] audValueArray = jwtClaims.getStringArrayClaim(audClaim);

        if (audValueArray != null) {
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
            dataProvider = "replaceExpiresInClaim", dependsOnMethods = "testTokenScopeAddOperation")
    public void testTokenExpiresInClaimReplaceOperation(String expiresInClaim, long expiresIn) throws Exception {
        JWTClaimsSet jwtClaims = applicationUtil.extractJwtClaims(accessToken);

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
        JWTClaimsSet jwtClaims = applicationUtil.extractJwtClaims(accessToken);

        String scopeString = jwtClaims.getStringClaim(scope);
        String[] scopes = scopeString.split("\\s+");;

        Assert.assertFalse(ArrayUtils.contains(scopes, removedScope));
    }

    @DataProvider(name = "removeAUDClaim")
    public Object[][] removeAUDClaim() {
        return new Object[][]{
                {"aud", "zzz2.com"}
        };
    }
    @Test(groups = "wso2.is", description = "Check if the aud claim is present in the access token",
            dataProvider = "removeAUDClaim", dependsOnMethods = "testTokenAudClaimReplaceOperation")
    public void testTokenAudClaimRemoveOperation(String audClaim, String removedAud) throws Exception {
        JWTClaimsSet jwtClaims = applicationUtil.extractJwtClaims(accessToken);
        String[] audValueArray = jwtClaims.getStringArrayClaim(audClaim);

        if (audValueArray != null) {
            Assert.assertFalse(ArrayUtils.contains(audValueArray, removedAud));
        } else {
            String audValueString = jwtClaims.getStringClaim(audClaim);
            Assert.assertNotEquals(audValueString, removedAud);
        }
    }
}
