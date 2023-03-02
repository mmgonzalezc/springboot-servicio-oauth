package com.formacionbdi.springboot.app.oauth.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService usuarioService;
    /***
     * Inyectamos eventPublisher -> Para poder registrar este evento en spring security
     */
    @Autowired
    private AuthenticationEventPublisher eventPublisher;

    /**
     * @return
     * @Bean -> Registra en contenedor de spring
     * <p>
     * Para encriptar nuestras constraseñas
     * Lo que retorna el metodo es lo que se registra como bean de spring
     */
    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    /***
     * Autowired -> para inyectar mediante metodo
     */
    @Autowired
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // passwordEncoder -> Encripta en automatico el password cuano el usuario ingrese su contraseña en el login
        auth.userDetailsService(this.usuarioService).passwordEncoder(passwordEncoder())
                .and().authenticationEventPublisher(eventPublisher);// Registramos el evento
    }

    @Override
    @Bean
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }


}
