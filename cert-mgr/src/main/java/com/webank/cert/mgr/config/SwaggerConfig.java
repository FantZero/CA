package com.webank.cert.mgr.config;

import io.swagger.annotations.ApiOperation;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.oas.annotations.EnableOpenApi;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.service.Contact;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;

/**
 * @author jiangzhe
 * @create 2022/3/10 14:39
 */
@Configuration    //表明当前类是配置类
@EnableOpenApi    //表示开启生成接口文档功能（只有开启了OpenApi,才可以实现生成接口文档的功能）
public class SwaggerConfig {
    @Bean
    public Docket createRestApi() {
        return new Docket(DocumentationType.OAS_30)
                .apiInfo(apiInfo())
                .select()
                .apis( RequestHandlerSelectors.withMethodAnnotation(ApiOperation.class))
                .paths(PathSelectors.any())
                .build();
    }

    private ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                .title("CA证书服务项目接口文档")//标题
                .description("更多请咨询服务开发者 江哲")//描述
                //附加信息
                .contact(new Contact("", "", "jiangzhe01@whty.com.cn"))
                .version("1.0")//版本
                .build();
    }
}
