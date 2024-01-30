package com.sid.keycloakauthenticator;

import java.util.List;
import javax.ws.rs.core.MultivaluedMap;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.events.Errors;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.UserModel;
import org.keycloak.services.messages.Messages;

/**
 * Mobile Authenticator for Keycloak
 */
public class MobileAuthenticator extends UsernamePasswordForm implements Authenticator {

    @Override
    public boolean validateUserAndPassword(AuthenticationFlowContext context, MultivaluedMap<String, String> inputData) {
        String username = inputData.getFirst(USERNAME);
        if (username == null || username.trim().isEmpty()) {
            context.getEvent().error(Errors.USER_NOT_FOUND);
            context.failureChallenge(AuthenticationFlowError.INVALID_USER, challengeResponse(context, Messages.INVALID_USER));
            return false;
        }

        UserModel user = null;
        try {
            List<UserModel> users = context.getSession().users().searchForUserByUserAttribute("mobile", username, context.getRealm());
            if (users != null && users.size() == 1) {
                user = users.get(0);
            }
        } catch (ModelDuplicateException mde) {
            if (mde.getDuplicateFieldName() != null && mde.getDuplicateFieldName().equals(UserModel.EMAIL)) {
                setDuplicateUserChallenge(context, Errors.EMAIL_IN_USE, Messages.EMAIL_EXISTS, AuthenticationFlowError.INVALID_USER);
            } else {
                setDuplicateUserChallenge(context, Errors.USERNAME_IN_USE, Messages.USERNAME_EXISTS, AuthenticationFlowError.INVALID_USER);
            }
            return false;
        }

        if (invalidUser(context, user)) {
            return false;
        }

        if (!validatePassword(context, user, inputData)) {
            return false;
        }

        if (!enabledUser(context, user)) {
            return false;
        }

        context.setUser(user);

        return true;
    }
}
