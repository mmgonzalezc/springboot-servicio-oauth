package com.formacionbdi.springboot.app.oauth.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.context.config.annotation.RefreshScope;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/***
 * RefreshScope Anotacion que nos permite actualizar en tiempo real mediante una url de spring actuator los
 * componentes, controlodores, clases anotados con component, service , controllers
 * que le estemos enyectando con @Value.
 */
@RefreshScope
@Configuration
/***
 * EnableAuthorizationServer -> Habilita clase como servidor de autorizacion
 */
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    @Autowired
    private Environment env;
    /***
     * Inyectamos el bean BCryptPasswordEncoder configurado en la clase de SpringSecurityConfig
     */
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    /***
     * Inyectamos el bean AuthenticationManager configurado en la clase de SpringSecurityConfig
     */
    @Autowired
    private AuthenticationManager authenticationManager;

    /***
     * Inyectamos componente InfoAdicionalToken para agregarlo a lista de informacion adicional token
     */
    @Autowired
    private InfoAdicionalToken infoAdicionalToken;

    /***
     * Configuracion de permisos de nuestros endpoints del servidor de autorizacion oauth2 para generar el token y validar token
     * Metodos de spring security
     * permitAll() -> Cualquier cliente puede acceder a la ruta para generar el token
     * isAuthenticated() -> Valida que el cliente este autenticado
     * @param security
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security.tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()");
    }

    /***
     * Configuracion de nuestros clientes
     * @param clients
     * @throws Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory().withClient(env.getProperty("config.security.oauth.client.id"))
                .secret(passwordEncoder.encode(env.getProperty("config.security.oauth.client.secret")))
                .scopes("read", "write")
                .authorizedGrantTypes("password", "refresh_token")
                .accessTokenValiditySeconds(3600)
                .refreshTokenValiditySeconds(3600);
    }

    /***
     * Configuracion de endpoints de oauth2
     * @param endpoints
     * @throws Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        // Creamos instancia para unir la informacion adicional al token
        TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
        tokenEnhancerChain.setTokenEnhancers(Arrays.asList(infoAdicionalToken, accessTokenConverter()));
        // Registramos el authenticationManager
        endpoints.authenticationManager(authenticationManager)
                .tokenStore(tokenStore())
                .accessTokenConverter(accessTokenConverter())
                /**
                 * Agregamos a la configuracion del endpoint tokenEnhancerChain
                 */
                .tokenEnhancer(tokenEnhancerChain);
    }

    /**
     * Se generara como componente de spring pra la configuracion
     *
     * @return
     */
    @Bean
    /***
     * Componente que se encarga de guardar el token con los datos del accessTokenConverter
     */
    public JwtTokenStore tokenStore() {
        return new JwtTokenStore(accessTokenConverter());
    }

    /**
     * Se generara como componente de spring pra la configuracion
     *
     * @return
     */
    @Bean
    /***
     * Se encarga de guardar los datos del usuario en el token codificados en base 64
     */
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter tokenConverter = new JwtAccessTokenConverter();
        // Codificacmos llave en base 64 para que sea mas robusta y sea conpatible con el metodo authenticate en api gateway
        tokenConverter.setSigningKey(Base64.getEncoder().encodeToString(Objects.requireNonNull(env.getProperty("config.security.oauth.jwt.key")).getBytes()));// Asigna llave secreta
        return tokenConverter;
    }


}
