﻿using System;
using Casbin.AspNetCore.Core.Abstractions;
using Casbin.AspNetCore.Core.Policy;
using Casbin.AspNetCore.Core.Transformers;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Casbin.AspNetCore.Core
{
    public static class ServiceCollectionExtension
    {
        public static IServiceCollection AddCasbinAuthorizationCore(
            this IServiceCollection services,
            Action<CasbinAuthorizationCoreOptions> configure,
            ServiceLifetime defaultModelProviderLifeTime = ServiceLifetime.Scoped,
            ServiceLifetime defaultEnforcerProviderLifeTime = ServiceLifetime.Scoped)
        {
            var options = new CasbinAuthorizationCoreOptions();
            configure(options);
            CheckOptions(options);
            services.Configure(configure);
            services.TryAdd(ServiceDescriptor.Describe(
                typeof(ICasbinModelProvider), typeof(DefaultCasbinModelProvider),
                defaultModelProviderLifeTime));
            services.TryAdd(ServiceDescriptor.Describe(
                typeof(IEnforcerProvider), typeof(DefaultEnforcerProvider),
                defaultEnforcerProviderLifeTime));
            services.TryAddSingleton<
                ICasbinAuthorizationContextFactory,
                DefaultCasbinAuthorizationContextFactory>();
            services.TryAddScoped<IAuthorizationHandler, CasbinAuthorizationHandler>();
            services.TryAddScoped<IEnforceService, DefaultEnforcerService>();
            services.AddSingleton<IRequestTransformer, BasicRequestTransformer>();
            services.AddAuthorizationCore();
            return services;
        }

        private static void CheckOptions(CasbinAuthorizationCoreOptions options)
        {
            if (options.DefaultEnforcerFactory is null)
            {
                throw new ArgumentNullException(nameof(options.DefaultEnforcerFactory));
            }
        }
    }
}
