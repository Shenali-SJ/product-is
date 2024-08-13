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

package org.wso2.identity.integration.test.restclients;

import io.restassured.http.ContentType;
import org.apache.commons.codec.binary.Base64;
import org.apache.http.Header;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.message.BasicHeader;
import org.wso2.carbon.automation.engine.context.beans.Tenant;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.identity.integration.test.rest.api.server.action.management.v1.model.ActionModel;
import org.wso2.identity.integration.test.utils.OAuth2Constant;

import java.io.IOException;

public class ActionsRestClient extends RestBaseClient {

    private final String serverUrl;
    private final String tenantDomain;
    private final String username;
    private final String password;
    private final String actionsBasePath;

    private static final String PRE_ISSUE_ACCESS_TOKEN_TYPE = "preIssueAccessToken";
    private static final String ACTIONS_PATH = "/actions";
    private static final String PRE_ISSUE_ACCESS_TOKEN_PATH = "/preIssueAccessToken";
    public ActionsRestClient(String serverUrl, Tenant tenantInfo) {

        this.serverUrl = serverUrl;
        this.tenantDomain = tenantInfo.getContextUser().getUserDomain();
        this.username = tenantInfo.getContextUser().getUserName();
        this.password = tenantInfo.getContextUser().getPassword();

        actionsBasePath = getActionsPath(serverUrl, tenantDomain);
    }

    public int createActionType(ActionModel actionModel, String actionType) throws IOException {
        String jsonRequestBody = toJSONString(actionModel);

        String endPointUrl;
        switch (actionType) {
            case PRE_ISSUE_ACCESS_TOKEN_TYPE:
                endPointUrl = actionsBasePath + PRE_ISSUE_ACCESS_TOKEN_PATH;
                break;
            default:
                endPointUrl = "";
        }

        try (CloseableHttpResponse response = getResponseOfHttpPost(endPointUrl, jsonRequestBody, getHeaders())) {
            return response.getStatusLine().getStatusCode();
        }
    }
    private String getActionsPath (String serverUrl, String tenantDomain) {

        if (tenantDomain.equals(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME)) {
            return serverUrl + API_SERVER_PATH + ACTIONS_PATH;
        } else {
            return serverUrl + TENANT_PATH + tenantDomain + PATH_SEPARATOR + API_SERVER_PATH +
                    ACTIONS_PATH;
        }
    }

    private Header[] getHeaders() {

        Header[] headerList = new Header[3];
        headerList[0] = new BasicHeader(USER_AGENT_ATTRIBUTE, OAuth2Constant.USER_AGENT);
        headerList[1] = new BasicHeader(AUTHORIZATION_ATTRIBUTE, BASIC_AUTHORIZATION_ATTRIBUTE +
                Base64.encodeBase64String((username + ":" + password).getBytes()).trim());
        headerList[2] = new BasicHeader(CONTENT_TYPE_ATTRIBUTE, String.valueOf(ContentType.JSON));

        return headerList;
    }
}
