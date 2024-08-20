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

import org.wso2.carbon.automation.engine.context.TestUserMode;
import org.wso2.identity.integration.common.clients.oauth.OauthAdminClient;
import org.wso2.identity.integration.common.utils.ISIntegrationTest;
import org.wso2.identity.integration.test.rest.api.server.action.management.v1.model.ActionModel;
import org.wso2.identity.integration.test.rest.api.server.action.management.v1.model.AuthenticationType;
import org.wso2.identity.integration.test.rest.api.server.action.management.v1.model.Endpoint;
import org.wso2.identity.integration.test.restclients.ActionsRestClient;

public class ActionsBaseTestCase extends ISIntegrationTest {
    protected ActionsRestClient restClient;
    protected OauthAdminClient adminClient;
    private static final String PRE_ISSUE_ACCESS_TOKEN_TYPE = "preIssueAccessToken";

    /**
     * Initialize.
     *
     * @param userMode - User Id.
     * @throws Exception If an error occurred while initializing the clients.
     */
    protected void init(TestUserMode userMode) throws Exception {

        super.init(userMode);

        restClient = new ActionsRestClient(serverURL, tenantInfo);
        adminClient = new OauthAdminClient(backendURL, sessionCookie);
    }

    public int createPreIssueAccessTokenType(String uri) {
        AuthenticationType authenticationType = new AuthenticationType();
        authenticationType.setType(AuthenticationType.TypeEnum.BASIC);

        Endpoint endpoint = new Endpoint();
        endpoint.setUri(uri);
        endpoint.setAuthentication(authenticationType);

        ActionModel actionModel = new ActionModel();
        actionModel.setName("Access Token Pre Issue");
        actionModel.setDescription("This is a test pre issue access token type");
        actionModel.setEndpoint(endpoint);

        try {
            return restClient.createActionType(actionModel, PRE_ISSUE_ACCESS_TOKEN_TYPE);
        } catch (Exception e) {
            throw new RuntimeException("Error while creating action of type pre issue access token for: " + actionModel.getName());
        }
    }
}
