package security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.support.SpringBootServletInitializer;

/**
 *
 * 也可以继承{@link SpringBootServletInitializer}
 *
 * <pre>
 *     protected SpringApplicationBuilder configure(SpringApplicationBuilder builder) {
 *         return builder.sources(App.class);
 *     }
 * </pre>
 *
 * @author xinchen
 * @version 1.0
 * @date 30/09/2019 14:07
 */
@SpringBootApplication
public class App {
    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }
}
