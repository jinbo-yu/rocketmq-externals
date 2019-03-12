/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package org.apache.rocketmq.console.config;

import com.alibaba.fastjson.JSON;
import java.util.List;
import org.apache.commons.lang3.RandomStringUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Value;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configurers.provisioning.UserDetailsManagerConfigurer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${spring.security.user.json}")
    String userJson;

    @Override
    protected void configure(AuthenticationManagerBuilder auth)
        throws Exception {
        if (StringUtils.isEmpty(userJson)) {
            return;
        }

        List<User> users = JSON.parseArray(userJson, User.class);
        for (User u : users) {
            if (StringUtils.isEmpty(u.password)) {
                u.setPassword(RandomStringUtils.random(12));
            }
        }
        if (users.size() > 0) {
            User u = users.get(0);
            String role = "USER";
            UserDetailsManagerConfigurer.UserDetailsBuilder udb = auth.inMemoryAuthentication().withUser(u.getUser()).password(u.getPassword()).roles(role);
            for (int i = 1; i < users.size(); i++) {
                u = users.get(i);
                udb.and().withUser(u.getUser()).password(u.getPassword()).roles(role);
            }
        }
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
            .authorizeRequests()
            .anyRequest().authenticated()
            .and()
            .formLogin().and()
            .httpBasic();
        http.csrf().disable();
    }
}

