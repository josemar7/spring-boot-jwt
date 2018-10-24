package com.bolsadeideas.springboot.app;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import com.bolsadeideas.springboot.app.auth.filter.JWTAuthenticationFilter;
import com.bolsadeideas.springboot.app.auth.filter.JWTAuthorizationFilter;
import com.bolsadeideas.springboot.app.auth.handler.LoginSuccesHandler;
import com.bolsadeideas.springboot.app.auth.service.JWTService;
import com.bolsadeideas.springboot.app.models.service.JpaUserDetailsService;

@EnableGlobalMethodSecurity(securedEnabled=true, prePostEnabled=true)
@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {
	
	@Autowired
	private LoginSuccesHandler successHandler; 
	
	@Autowired
	private DataSource dataSource;
	
	@Autowired
	private BCryptPasswordEncoder passwordEncoder;
	
	@Autowired
	private JpaUserDetailsService jpaUserDetailsService;
	
	@Autowired
	private JWTService jWTService;
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().antMatchers("/", "/css/**", "/js/**", "/images/**", "/listar**", "/locale").permitAll()
//		.antMatchers("/ver/**").hasAnyRole("USER")
//		.antMatchers("/uploads/**").hasAnyRole("USER")
//		.antMatchers("/form/**").hasAnyRole("ADMIN")
//		.antMatchers("/eliminar/**").hasAnyRole("ADMIN")
//		.antMatchers("/factura/**").hasAnyRole("ADMIN")
		.anyRequest().authenticated()
//		.and()
//		.formLogin()
//		.successHandler(successHandler)
//		.loginPage("/login")
//		.permitAll()
//		.and()
//		.logout().permitAll()
//		.and()
//		.exceptionHandling()
//		.accessDeniedPage("/error_403")
		.and()
		.addFilter(new JWTAuthenticationFilter(authenticationManager(), jWTService))
		.addFilter(new JWTAuthorizationFilter(authenticationManager(), jWTService))
		.csrf()
		.disable()
		.sessionManagement()
		.sessionCreationPolicy(SessionCreationPolicy.STATELESS);
	}

	@Autowired
	public void configurerGlobal(AuthenticationManagerBuilder build) throws Exception {
//		build.jdbcAuthentication()
//		.dataSource(dataSource)
//		.passwordEncoder(passwordEncoder)
//		.usersByUsernameQuery("select username, password, enabled from users where username=?")
//		.authoritiesByUsernameQuery("select u.username, a.authority from authorities a inner join users u on (a.user_id=u.id) where u.username=?");
		
		build.userDetailsService(jpaUserDetailsService)
		.passwordEncoder(passwordEncoder);

//		UserBuilder users = User.withDefaultPasswordEncoder();
//		build.inMemoryAuthentication()
//		.withUser(users.username("admin").password("12345").roles("ADMIN", "USER"))
//		.withUser(users.username("andres").password("12345").roles("USER"));
	}

}
