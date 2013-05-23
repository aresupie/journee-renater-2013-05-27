package fr.cnrs.dsi.journee.federation.renater;

import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.apache.cxf.configuration.security.AuthorizationPolicy;
import org.apache.cxf.jaxrs.ext.MessageContext;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Cookie;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Set;

import static javax.ws.rs.core.Response.Status.*;

@Path("/")
public class ExtractJanusCookie {

	/**
	 * Récupère le cookie de Janus. Pour cela, ce WS n'est pas protégé par Janus, mais demande une authentification par
	 * login/pass via le protocole HTTP
	 *
	 * @param url l'url du WS qui sera appelé au final
	 * @param mc  injecté par CXF
	 *
	 * @return le cookie sous forme textuelle, avec les champs suivants (séparateur ';') : domain, path, version, name,
	 *         value
	 *
	 * @throws IOException
	 */
	@GET
	@Path("/cookie")
	@Produces("text/plain")
	public Response janusCookie(@QueryParam("url") String url, @Context MessageContext mc) throws IOException {
		AuthorizationPolicy policy = (AuthorizationPolicy) mc.get("org.apache.cxf.configuration.security.AuthorizationPolicy");
		if (policy != null) {
			String username = policy.getUserName();
			String password = policy.getPassword();
			final Cookie cookie = retrieveJanusCookie(url, username, password);

			if (cookie == null) {
				return Response.status(INTERNAL_SERVER_ERROR).entity("Cannot retrieve Janus Cookie").build();
			}

			final String domain = cookie.getDomain();
			final String name = cookie.getName();
			final String path = cookie.getPath();
			final String value = cookie.getValue();
			final int version = cookie.getVersion();

			String entity = new StringBuilder(domain).append(';').append(path).append(';').append(version).append(';').append(name).append(';').append(value).toString();

			return Response.status(OK).entity(entity).build();
		} else {
			// request the authentication, add the realm name if needed to the value of WWW-Authenticate
			return Response.status(UNAUTHORIZED).header("WWW-Authenticate", "Basic").build();
		}
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
	private Cookie retrieveJanusCookie(final String baseAddress, final String username, final String password) throws IOException {
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
		return extractJanusCookie(wc.getCookieManager().getCookies());
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
}

