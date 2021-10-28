package life.qbic.data.security;

import com.vaadin.flow.spring.security.VaadinWebSecurityConfigurerAdapter;
import life.qbic.data.views.login.LoginView;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
@Configuration
@PropertySource(value = "classpath:/application.properties", ignoreResourceNotFound = true)
@ConfigurationProperties(prefix = "auth.ldap")
public class LdapSecurityConfiguration extends VaadinWebSecurityConfigurerAdapter {

  @Value("${auth.ldap.url}")
  private String ldap_url;

  @Value("${auth.ldap.password}")
  private String ldap_passwd;

  public static final String LOGOUT_URL = "/";

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    // Set default security policy that permits Vaadin internal requests and
    // denies all other
    super.configure(http);
    setLoginView(http, LoginView.class, LOGOUT_URL);
  }

  @Override
  public void configure(WebSecurity web) throws Exception {
    super.configure(web);
    web.ignoring().antMatchers("/images/*.png");
  }

  @Override
  protected void configure(AuthenticationManagerBuilder auth) throws Exception {
    // Obtain users and roles from an LDAP service
    auth.ldapAuthentication()
        .userDnPatterns("cn=qbic-reader,ou=kommdb,o=Universitaet Tuebingen,c=DE")
        .userSearchBase("o=Universitaet Tuebingen,c=DE?subtree?")
        .groupSearchBase("o=Universitaet Tuebingen,c=DE")
        .contextSource()
        .url(ldap_url)
        .and()
        .passwordCompare()
        .passwordAttribute(ldap_passwd);
  }
}
