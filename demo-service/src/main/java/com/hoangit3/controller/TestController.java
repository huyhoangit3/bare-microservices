package com.hoangit3.controller;

import com.hoangit3.annotation.RoleAdmin;
import com.hoangit3.annotation.RoleAdminOrUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(path = "/api/demo")
public class TestController {
    @GetMapping(path = "hello")
    @RoleAdmin
    public String sayHello() {
        return "Hello demo service - admin";
    }

    @GetMapping(path = "hello2")
//    @RoleAdminOrUser
    public String sayHello2() {
        return "Hello demo service - admin or user";
    }
}
