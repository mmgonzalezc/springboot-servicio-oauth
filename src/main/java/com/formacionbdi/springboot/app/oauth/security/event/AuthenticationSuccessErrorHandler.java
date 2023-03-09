package com.formacionbdi.springboot.app.oauth.security.event;

import brave.Tracer;
import com.formacionbdi.springboot.app.oauth.services.IUsuarioService;
import com.formacionbdi.springboot.app.commons.usuarios.models.entity.Usuario;
import feign.FeignException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

import java.util.Objects;

/***
 * Tenemos que implementar de la interfaz para que podamos manejar el exito y el error
 */
@Component
public class AuthenticationSuccessErrorHandler implements AuthenticationEventPublisher {
    private Logger LOGGER = LoggerFactory.getLogger(AuthenticationSuccessErrorHandler.class);

    @Autowired
    private IUsuarioService usuarioService;

    /***
     * Dependencia para poder agregar trazabilidad de logs a zipkin
     */
    @Autowired
    private Tracer tracer;

    @Override
    public void publishAuthenticationSuccess(Authentication authentication) {
        /***
         * Validacion para omitir evento de cliente que no es nuestro
         */
        if (authentication.getDetails() instanceof WebAuthenticationDetails) {
            return;
        }
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String mensaje = "Success Login: " + userDetails.getUsername();
        System.out.println(mensaje);
        LOGGER.info(mensaje);
        Usuario usuario = usuarioService.findByUsername(authentication.getName());
        if (Objects.nonNull(usuario.getIntentos()) && usuario.getIntentos() > 0) {
            usuario.setIntentos(0);
            usuarioService.update(usuario, usuario.getId());
        }
    }

    @Override
    public void publishAuthenticationFailure(AuthenticationException exception, Authentication authentication) {
        String mensaje = "Error en el Login: " + exception.getMessage();
        LOGGER.error(mensaje);
        try {
            StringBuilder errors = new StringBuilder();
            errors.append(mensaje);
            Usuario usuario = usuarioService.findByUsername(authentication.getName());
            // Null es el estado inicial
            if (Objects.isNull(usuario.getIntentos())) {
                usuario.setIntentos(0);
            }
            LOGGER.info("Intentos actual es de: " + usuario.getIntentos());
            usuario.setIntentos(usuario.getIntentos() + 1);
            LOGGER.info("Intentos despues es de: " + usuario.getIntentos());
            errors.append(" - Intentos del login: " + usuario.getIntentos());
            if (usuario.getIntentos() >= 3) {
                String errorMaxIntentos = String.format("El usuario %s des-habilitado por máximos intentos.", usuario.getUsername());
                LOGGER.error(errorMaxIntentos);
                errors.append(" - " + errorMaxIntentos);
                usuario.setEnabled(false);
            }
            usuarioService.update(usuario, usuario.getId()); // Desavilitamos el usuarios
        tracer.currentSpan().tag("error.mensaje", errors.toString());
        } catch (FeignException e) {
            LOGGER.error(String.format("El usuario %s no existe en el sistema", authentication.getName()));
        }

    }
}
