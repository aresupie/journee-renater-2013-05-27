package fr.cnrs.dsi.journee.federation.renater;

import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.cxf.transport.http.HTTPConduit;
import org.junit.Before;
import org.junit.Test;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.ws.rs.RedirectionException;
import javax.ws.rs.core.Cookie;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Set;

import static javax.ws.rs.core.MediaType.TEXT_XML;
import static junit.framework.Assert.assertNotNull;

public class TestCallJanusProtectedWS {

	private final String BASE_ADDRESS = "https://webservice-dev.dsi.cnrs.fr/services/rs/sample/infos"; // C'est le lien vers le WS
	private final String PATH = "userinfo";
	private final String LOGIN = "stephane.deraco@dsi.cnrs.fr"; // C'est le login Janus
	private final String PASSWORD = "supermotdepasse"; // TODO : A modifier ; c'est le mot de passe Janus
	private Cookie janusCookie;
	private WebClient webClient;

	@Test
	public void testCallJanusProtectedWS() throws Exception {
		String data; // On peut remplacer cela par un objet métier

		try {
			// On appelle le WS avec le cookie Janus
			// On peut demander à ce qu'il fasse le mapping du résultat du WS vers notre objet métier, en
			// mettant par exemple "get(MonObjetMetier.class)" s'il est annoté avec du JAXB
			data = webClient.cookie(janusCookie).path(PATH).get(String.class);
		} catch (RedirectionException re) {
			// Si on a un REDIRECT, c'est que le cookie fourni n'est plus valide, il faut
			// qu'on en récupère un nouveau et qu'on relance la requête. Si jamais on a
			// de nouveau une erreur, c'est un autre problème.
			retrieveJanusCookie(BASE_ADDRESS, LOGIN, PASSWORD);
			data = webClient.cookie(janusCookie).path(PATH).get(String.class);
		}

		assertNotNull(data);
		// On peut maintenant travailler avec nos données
	}

	@Before
	public void setUp() throws Exception {
		// Récupération du Cookie Janus avec HtmlUnit
		retrieveJanusCookie(BASE_ADDRESS, LOGIN, PASSWORD);

		// Si on n'a pas réussi à le récupérer, ça ne sert à rien de continuer
		if (janusCookie == null) {
			throw new Exception("Cannot retrieve Janus Cookie");
		}

		// Création du client CXF
		webClient = WebClient.create(BASE_ADDRESS).accept(TEXT_XML);
		enableTrustAll(webClient); // Pour passer outre le certificat auto-signé
	}

	/**
	 * Récupération du Cookie fourni par Janus une fois l'authentification réalisée. La récupération se fait avec
	 * HtmlUnit.
	 *
	 * @param baseAddress l'adresse de base de la ressource
	 * @param username    login Janus
	 * @param password    mot de passge Janus
	 *
	 * @throws java.io.IOException
	 */
	private void retrieveJanusCookie(final String baseAddress, final String username, final String password) throws IOException {
		// HtmlUnit va récupérer la page définie par <protocole>://<host>, pour éviter de déclencher le WS
		String host = getHost(baseAddress);

		// Client HtmlUnit
		final com.gargoylesoftware.htmlunit.WebClient wc = new com.gargoylesoftware.htmlunit.WebClient();
		wc.getOptions().setUseInsecureSSL(true); // Pour passer outre le certificat auto-signé
		wc.getOptions().setThrowExceptionOnFailingStatusCode(false); // Si on reçoit un 404 en fin de chaine, c'est pas grave (du moment qu'on a le cookie)

		// Page de login de Janus
		final HtmlPage janusLoginPage = wc.getPage(host);
		final HtmlForm janusLoginForm = janusLoginPage.getForms().get(0);

		// On met le login et le pass
		janusLoginForm.getInputByName("username").setValueAttribute(username);
		janusLoginForm.getInputByName("password").setValueAttribute(password);

		// On valide le formulaire
		janusLoginForm.getInputByName("submit").click();

		// Ce cookie est une instance de javax.ws.rs.core.Cookie (et pas le Cookie de HtmlUnit)
		this.janusCookie = extractJanusCookie(wc.getCookieManager().getCookies());
	}

	/**
	 * Extrait le cookie Janus (_shibsession_*) à partir de la liste des cookies récupérés par HtmlUnit
	 *
	 * @param cookies l'ensemble des cookies (com.gargoylesoftware.htmlunit.util.Cookie) récupérés par HtmlUnit
	 *
	 * @return le cookie (javax.ws.rs.core.Cookie) correspondant au cookie Shibboleth si présent, null sinon
	 */
	private Cookie extractJanusCookie(final Set<com.gargoylesoftware.htmlunit.util.Cookie> cookies) {
		if (cookies != null) {
			for (com.gargoylesoftware.htmlunit.util.Cookie c : cookies) {
				if (c.getName().startsWith("_shibsession_")) {
					return new Cookie(c.getName(), c.getValue(), c.getPath(), c.getDomain());
				}
			}
		}

		return null;
	}

	/**
	 * Retourne uniquement le protocole et l'hôte à partir de l'url de base du WS
	 *
	 * @param baseAddress url de base du WS
	 *
	 * @return {@code <protocole>://<host>}
	 *
	 * @throws java.net.MalformedURLException
	 */
	private String getHost(final String baseAddress) throws MalformedURLException {
		final URL url = new URL(baseAddress);
		return String.format("%s://%s", url.getProtocol(), url.getHost());
	}

	/**
	 * Informe le client CXF d'accepter les certificats auto-signés
	 *
	 * @param webClient
	 */
	private void enableTrustAll(final WebClient webClient) {
		HTTPConduit conduit = WebClient.getConfig(webClient).getHttpConduit();

		TLSClientParameters params = conduit.getTlsClientParameters();

		if (params == null) {
			params = new TLSClientParameters();
			conduit.setTlsClientParameters(params);
		}

		params.setTrustManagers(new TrustManager[]{new X509TrustManager() {
			@Override
			public void checkClientTrusted(final X509Certificate[] x509Certificates, final String s) throws CertificateException {
				// noop
			}

			@Override
			public void checkServerTrusted(final X509Certificate[] x509Certificates, final String s) throws CertificateException {
				// noop
			}

			@Override
			public X509Certificate[] getAcceptedIssuers() {
				return new X509Certificate[0];
			}
		}});
		params.setDisableCNCheck(true);
	}
}
