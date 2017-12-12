/*
 * (C) Copyright 2015 Nuxeo SA (http://nuxeo.com/) and contributors.
 *
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the GNU Lesser General Public License
 * (LGPL) version 2.1 which accompanies this distribution, and is available at
 * http://www.gnu.org/licenses/lgpl-2.1.html
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * Contributors:
 *  Vladimir Pasquier <vpasquier@nuxeo.com>
 */
package org.nuxeo.shibboleth.invitation;

import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;

import com.google.common.base.MoreObjects;
import com.google.common.collect.BiMap;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nuxeo.ecm.core.api.*;
import org.nuxeo.ecm.core.api.impl.DocumentModelImpl;
import org.nuxeo.ecm.core.api.repository.RepositoryManager;
import org.nuxeo.ecm.core.api.security.ACE;
import org.nuxeo.ecm.core.api.security.ACL;
import org.nuxeo.ecm.core.api.security.ACP;
import org.nuxeo.ecm.platform.shibboleth.service.ShibbolethAuthenticationService;
import org.nuxeo.ecm.platform.usermanager.NuxeoPrincipalImpl;
import org.nuxeo.ecm.platform.usermanager.UserManager;
import org.nuxeo.ecm.platform.web.common.vh.VirtualHostHelper;
import org.nuxeo.ecm.user.invite.AlreadyProcessedRegistrationException;
import org.nuxeo.ecm.user.invite.DefaultInvitationUserFactory;
import org.nuxeo.ecm.user.invite.UserInvitationService;
import org.nuxeo.ecm.user.invite.UserRegistrationException;
import org.nuxeo.ecm.user.registration.UserRegistrationService;
import org.nuxeo.ecm.webengine.forms.FormData;
import org.nuxeo.ecm.webengine.model.Template;
import org.nuxeo.ecm.webengine.model.WebObject;
import org.nuxeo.ecm.webengine.model.impl.ModuleRoot;
import org.nuxeo.runtime.api.Framework;

@Path("/shibboInvite")
@WebObject(type = "shibboInvite")
@Produces("text/html;charset=UTF-8")
public class ShibboInviteObject extends ModuleRoot {
    public static final String DEFAULT_REGISTRATION = "default_registration";
    private static final Log log = LogFactory.getLog(ShibboInviteObject.class);

    private DocumentModel findUser(String field, String userName) {
        log.trace("fuck findUser");
        Map<String, Serializable> query = new HashMap<>();
        query.put(field, userName);
        DocumentModelList users = Framework.getLocalService(UserManager.class).searchUsers(query, null);

        if (users.isEmpty()) {
            return null;
        }
        return users.get(0);
    }

    @GET
    @Path("shibboleth")
    public Object mapShibbolethUser(@Context HttpServletRequest httpServletRequest, @QueryParam("RequestId") final String requestID) {
        log.info("requestID:" + requestID);
        log.info("principal:" + getContext().getUserSession().getPrincipal());
        ShibbolethAuthenticationService shiboService = Framework.getService(ShibbolethAuthenticationService.class);
        final String userID = shiboService.getUserID(httpServletRequest);
        log.info("userID:" + userID);
        log.info("getUserInfoUsernameField:" +Framework.getLocalService(UserRegistrationService.class).getConfiguration(DEFAULT_REGISTRATION).getUserInfoUsernameField());
        new UnrestrictedSessionRunner(Framework.getService(RepositoryManager.class).getDefaultRepositoryName()) {
            @Override
            public void run() {
                DocumentModel doc = session.getDocument(new IdRef(requestID));
                // "userinfo:login"
                doc.setPropertyValue("userinfo:login", userID);
                log.info("groups:" + doc.getPropertyValue("userinfo:groups"));
                session.saveDocument(doc);
                DocumentModel target = session.getDocument(new IdRef(
                        (String) doc.getPropertyValue("docinfo:documentId")));
                NuxeoPrincipal targetPrincipal = Framework.getLocalService(UserManager.class).getPrincipal(userID);
                ACP acp = target.getACP();
                Map<String, Serializable> contextData = new HashMap<>();
                contextData.put("notify", true);
                contextData.put("comment", doc.getPropertyValue("registration:comment"));
                acp.addACE(ACL.LOCAL_ACL,
                        ACE.builder(targetPrincipal.getName(), (String) doc.getPropertyValue("docinfo:permission"))
                                .creator((String) doc.getPropertyValue("docinfo:creator"))
                                .contextData(contextData)
                                .build());
                target.setACP(acp, true);
                java.util.List<String> userGroups = targetPrincipal.getGroups();
                userGroups.addAll((java.util.List<String>)doc.getPropertyValue("userinfo:groups"));
                targetPrincipal.setGroups(userGroups);
                Framework.getLocalService(UserManager.class).updateUser(targetPrincipal.getModel());
                session.saveDocument(target);

            }
        }.runUnrestricted();
        return getView("UserCreated").arg("redirectUrl", "/");
    }


    @POST
    @Path("validate")
    public Object validateTrialForm(@FormParam("isShibbo") boolean isShibbo) {
        UserInvitationService usr = fetchService();

        FormData formData = getContext().getForm();
        String requestId = formData.getString("RequestId");
        String password = formData.getString("Password");
        String passwordConfirmation = formData.getString("PasswordConfirmation");
        String configurationName = formData.getString("ConfigurationName");

        // Check if the requestId is an existing one
        try {
            usr.checkRequestId(requestId);
        } catch (AlreadyProcessedRegistrationException ape) {
            return getView("ValidationErrorTemplate").arg("exceptionMsg",
                    ctx.getMessage("label.error.requestAlreadyProcessed"));
        } catch (UserRegistrationException ue) {
            return getView("ValidationErrorTemplate").arg("exceptionMsg",
                    ctx.getMessage("label.error.requestNotExisting", requestId));
        }

        if (!isShibbo) {
            // Check if both entered passwords are correct
            if (password == null || "".equals(password.trim())) {
                return redisplayFormWithErrorMessage("EnterPassword",
                        ctx.getMessage("label.registerForm.validation.password"), formData);

            }
            if (passwordConfirmation == null || "".equals(passwordConfirmation.trim()) && !isShibbo) {
                return redisplayFormWithErrorMessage("EnterPassword",
                        ctx.getMessage("label.registerForm.validation.passwordconfirmation"), formData);
            }
            password = password.trim();
            passwordConfirmation = passwordConfirmation.trim();
            if (!password.equals(passwordConfirmation) && !isShibbo) {
                return redisplayFormWithErrorMessage("EnterPassword",
                        ctx.getMessage("label.registerForm.validation.passwordvalidation"), formData);
            }
        }
        Map<String, Serializable> registrationData = null;
        try {
            Map<String, Serializable> additionalInfo = buildAdditionalInfos();
            // Add the entered password to the document model
            additionalInfo.put(DefaultInvitationUserFactory.PASSWORD_KEY, password);
            // Validate the creation of the user
//            registrationData = usr.validateRegistration(requestId, additionalInfo);
//            NuxeoPrincipalImpl userPrincipal = (NuxeoPrincipalImpl) registrationData.get("registeredUser");
//            DocumentModelImpl userDoc = (DocumentModelImpl) registrationData.get("registrationDoc");
//            log.info("userDoc:" + userDoc);
//            log.info("userPrincipal:" + userPrincipal);
        } catch (AlreadyProcessedRegistrationException ape) {
            log.info("Try to validate an already processed registration");
            return getView("ValidationErrorTemplate").arg("exceptionMsg",
                    ctx.getMessage("label.error.requestAlreadyProcessed"));
        } catch (UserRegistrationException ue) {
            log.warn("Unable to validate registration request", ue);
            return getView("ValidationErrorTemplate").arg("exceptionMsg",
                    ctx.getMessage("label.error.requestNotAccepted"));
        }
        // User redirected to the logout page after validating the password
        String webappName = VirtualHostHelper.getWebAppName(getContext().getRequest());
        String redirectUrl = "/" + webappName + "/logout";
        if (isShibbo) {
//            return getView("UserCreated").arg("data", registrationData)
//                                         .arg("redirectUrl", "/nuxeo/site/shibboleth?requestedUrl=")
//                                         .arg("isShibbo", isShibbo);

            /*


            <form action="/nuxeo/site/shibboInvite/validate" method="post" enctype="application/x-www-form-urlencoded" name="submitShibboleth">
        <div>
            <input type="hidden" id="RequestId" value="9c5e94ec-7089-4ba2-9408-196455aa57ef" name="RequestId">
            <input type="hidden" id="ConfigurationName" value="default_registration" name="ConfigurationName">
            <input type="hidden" id="isShibbo" value="true" name="isShibbo">
            <input type="submit" name="submitShibbo" value="Choose Shibboleth Authentication">
        </div>
    </form>
             */



            String validationRelUrl = "https://nuxeo.universite-lyon.fr/" + usr.getConfiguration(configurationName).getValidationRelUrl()+ "?isShibbo=true&RequestId="+requestId+"&ConfigurationName="+configurationName;
            try {
                redirectUrl = "/nuxeo/login.jsp?requestedUrl=" + URLEncoder.encode(validationRelUrl, "UTF-8");
            } catch (UnsupportedEncodingException e) {
                log.error(e.getLocalizedMessage());
            }
            redirectUrl = "/nuxeo/site/shibboInvite/shibboleth?RequestId="+requestId;
//            return getView("UserCreated").arg("data", registrationData)
//                             .arg("redirectUrl", redirectUrl)
//                             .arg("isShibbo", isShibbo);
//            https://nuxeo.universite-lyon.fr/nuxeo/login.jsp?requestedUrl=
        }
        return getView("UserCreated").arg("redirectUrl", redirectUrl)
                                     .arg("data", registrationData)
                                     .arg("isShibbo", isShibbo);
    }

    protected UserInvitationService fetchService() {
        return Framework.getLocalService(UserRegistrationService.class);
    }

    @GET
    @Path("enterpassword/{configurationName}/{requestId}")
    public Object validatePasswordForm(@PathParam("requestId") String requestId,
            @PathParam("configurationName") String configurationName) {

        UserInvitationService usr = fetchService();
        try {
            usr.checkRequestId(requestId);
        } catch (AlreadyProcessedRegistrationException ape) {
            return getView("ValidationErrorTemplate").arg("exceptionMsg",
                    ctx.getMessage("label.error.requestAlreadyProcessed"));
        } catch (UserRegistrationException ue) {
            return getView("ValidationErrorTemplate").arg("exceptionMsg",
                    ctx.getMessage("label.error.requestNotExisting", requestId));
        }

        Map<String, String> data = new HashMap<String, String>();
        data.put("RequestId", requestId);
        data.put("ConfigurationName", configurationName);
        String webappName = VirtualHostHelper.getWebAppName(getContext().getRequest());
        String validationRelUrl = usr.getConfiguration(configurationName).getValidationRelUrl();
        String valUrl = "/" + webappName + "/" + validationRelUrl;
        data.put("ValidationUrl", valUrl);
        return getView("EnterPassword").arg("data", data);
    }

    protected Map<String, Serializable> buildAdditionalInfos() {
        return new HashMap<>();
    }

    protected Template redisplayFormWithMessage(String messageType, String formName, String message, FormData data) {
        Map<String, String> savedData = new HashMap<String, String>();
        for (String key : data.getKeys()) {
            savedData.put(key, data.getString(key));
        }
        return getView(formName).arg("data", savedData).arg(messageType, message);
    }

    protected Template redisplayFormWithInfoMessage(String formName, String message, FormData data) {
        return redisplayFormWithMessage("info", formName, message, data);
    }

    protected Template redisplayFormWithErrorMessage(String formName, String message, FormData data) {
        return redisplayFormWithMessage("err", formName, message, data);
    }

}
