package com.formacionbdi.springboot.app.oauth.clients;

import com.formacionbdi.springboot.app.usuarios.commons.models.entity.Usuario;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.*;


/***
 * servicio-usuarios servicio al que nos conectamos
 */
@FeignClient(name = "servicio-usuarios")
public interface UsuarioFeignClient {
    /**
     * Path buscar-username para consumir servicio-usuarios
     */
    @GetMapping("/usuarios/search/buscar-username")
    Usuario findByUsername(@RequestParam String username);


    @PutMapping("/usuarios/{id}")
    Usuario update(@RequestBody Usuario usuario, @PathVariable Long id);
}
