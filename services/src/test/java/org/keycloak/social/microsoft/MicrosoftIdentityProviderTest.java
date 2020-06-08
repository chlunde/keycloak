package org.keycloak.social.microsoft;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;
import org.apache.commons.io.Charsets;
import org.apache.commons.io.IOUtils;
import org.junit.Assert;
import org.junit.Test;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.broker.oidc.OAuth2IdentityProviderConfig;
import org.keycloak.social.microsoft.MicrosoftIdentityProvider;

import java.net.URL;
import java.util.List;
import java.util.Arrays;

public class MicrosoftIdentityProviderTest {
	private final String TEST_TRANSITIVE_MEMBER_OF_FILE = "/org/keycloak/test/social/microsoft/transitiveMemberOf.json";

    @Test
    public void testExtractingGroups() throws Exception {
        //given
        URL memberFile = MicrosoftIdentityProviderTest.class.getResource(TEST_TRANSITIVE_MEMBER_OF_FILE);

        String memberData = IOUtils.toString(memberFile, Charsets.toCharset("UTF-8"));

        ObjectMapper objectMapper = new ObjectMapper();
        JsonNode memberDataResponse = objectMapper.readTree(memberData);
		OAuth2IdentityProviderConfig config = new OAuth2IdentityProviderConfig(new IdentityProviderModel());

		MicrosoftIdentityProvider provider = new MicrosoftIdentityProvider(null, config);

        //when
		List<String> groups = provider.extractGroups(memberDataResponse);

        //then
        Assert.assertEquals(groups, Arrays.asList("All Users", "Developers"));
    }
}
