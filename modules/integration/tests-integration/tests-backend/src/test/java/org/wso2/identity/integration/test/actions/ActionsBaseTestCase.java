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
import org.wso2.identity.integration.test.rest.api.server.action.management.v1.model.Endpoint;
import org.wso2.identity.integration.test.restclients.ActionsRestClient;

public class ActionsBaseTestCase extends ISIntegrationTest {
    protected ActionsRestClient restClient;
    protected OauthAdminClient adminClient;

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

    public int createActionType(ActionModel actionModel, String actionType) {
        try {
            return restClient.createActionType(actionModel, actionType);
        } catch (Exception e) {
            throw new RuntimeException("Error while creating the action type: " + actionType);
        }
    }
}
