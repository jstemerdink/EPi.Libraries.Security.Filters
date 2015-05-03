// Copyright© 2015 Jeroen Stemerdink. 
// 
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following
// conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.

using System;
using System.Linq;

using EPi.Libraries.Security.Filters.Models;

using EPiServer.Data.Dynamic;
using EPiServer.Logging;
using EPiServer.ServiceLocation;
using EPiServer.Shell.Composition;

using NWebsec.Mvc.HttpHeaders;

namespace EPi.Libraries.Security.Filters.Business.Configuration
{
    /// <summary>
    ///     The SecurityConfigurationProvider class
    /// </summary>
    /// <examples>
    ///     SecurityConfigurationProvider singleton = SecurityConfigurationProvider.Instance;
    /// </examples>
    public sealed class SecurityConfigurationProvider
    {
        /// <summary>
        ///     The synclock object.
        /// </summary>
        private static readonly object SyncLock = new object();

        /// <summary>
        ///     The one and only SecurityConfigurationProvider instance.
        /// </summary>
        private static volatile SecurityConfigurationProvider instance;

        private readonly ILogger log = LogManager.GetLogger(typeof(SecurityConfigurationProvider));

        /// <summary>
        ///     Prevents a default instance of the <see cref="SecurityConfigurationProvider" /> class from being created.
        /// </summary>
        private SecurityConfigurationProvider()
        {
            SecurityFilterConfiguration securityFilterConfiguration;

            using (
                DynamicDataStore store =
                    this.DynamicDataStoreFactory.Service.GetOrCreateStore(typeof(SecurityFilterConfiguration)))
            {
                securityFilterConfiguration = store.Items<SecurityFilterConfiguration>().FirstOrDefault();
            }

            if (securityFilterConfiguration == null)
            {
                securityFilterConfiguration = CreateNewConfiguration();
                this.SaveConfiguration(securityFilterConfiguration);
            }

            this.SecurityFilterConfiguration = securityFilterConfiguration;
        }

        private Injected<DynamicDataStoreFactory> DynamicDataStoreFactory { get; set; }

        /// <summary>
        ///     Gets or sets the security filter configuration.
        /// </summary>
        /// <value>The security filter configuration.</value>
        public SecurityFilterConfiguration SecurityFilterConfiguration { get; set; }

        /// <summary>
        ///     Gets the instance of the SecurityConfigurationProvider object.
        /// </summary>
        public static SecurityConfigurationProvider Instance
        {
            get
            {
                // Double checked locking
                if (instance != null)
                {
                    return instance;
                }

                lock (SyncLock)
                {
                    if (instance == null)
                    {
                        instance = new SecurityConfigurationProvider();
                    }
                }

                return instance;
            }
        }

        private static SecurityFilterConfiguration CreateNewConfiguration()
        {
            SecurityFilterConfiguration securityFilterConfiguration = new SecurityFilterConfiguration
                                                                          {
                                                                              DisableVersionHeaders 
                                                                                = true,
                                                                              AllowBaseUriFromSameDomain
                                                                                  = true,
                                                                              AllowChildSrcFromSameDomain
                                                                                  = true,
                                                                              AllowConnectionsFromSameDomain
                                                                                  = true,
                                                                              AllowFontsFromSameDomain
                                                                                  = true,
                                                                              AllowFormActionToSameDomain
                                                                                  = true,
                                                                              AllowFrameAncestorsFromSameDomain
                                                                                  = true,
                                                                              AllowFramesFromSameDomain
                                                                                  = true,
                                                                              AllowImagesFromSameDomain
                                                                                  = true,
                                                                              AllowMediaFromSameDomain
                                                                                  = true,
                                                                              AllowPluginsFromSameDomain
                                                                                  = true,
                                                                              AllowScriptsFromSameDomain
                                                                                  = true,
                                                                              AllowStylesFromSameDomain
                                                                                  = true,
                                                                              AllowUnsafeEval
                                                                                  = false,
                                                                              AllowUnsafeInline
                                                                                  = false,
                                                                              AllowUnsafeInlineStyles
                                                                                  = false,
                                                                              EnableContentSecurityPolicy
                                                                                  = true,
                                                                              EnableXContentTypeOptions
                                                                                  = true,
                                                                              EnableXDownloadOptions
                                                                                  = true,
                                                                              EnableXFrameOptions
                                                                                  = true,
                                                                              XFrameOptionsPolicy
                                                                                  =
                                                                                  SecurityFilterConfiguration
                                                                                  .SameOrigin
                                                                          };

            return securityFilterConfiguration;
        }

        /// <summary>
        /// Saves the configuration.
        /// </summary>
        /// <param name="securityFilterConfiguration">The security filter configuration.</param>
        public void SaveConfiguration(SecurityFilterConfiguration securityFilterConfiguration)
        {
            if (securityFilterConfiguration == null)
            {
                return;
            }

            using (
                DynamicDataStore store =
                    this.DynamicDataStoreFactory.Service.GetOrCreateStore(typeof(SecurityFilterConfiguration)))
            {
                try
                {
                    SecurityFilterConfiguration existingConfiguration =
                        store.Items<SecurityFilterConfiguration>().FirstOrDefault();

                    if (existingConfiguration != null)
                    {
                        existingConfiguration.DisableVersionHeaders = 
                            securityFilterConfiguration.DisableVersionHeaders;
                        existingConfiguration.AllowBaseUriFromSameDomain =
                            securityFilterConfiguration.AllowBaseUriFromSameDomain;
                        existingConfiguration.AllowChildSrcFromSameDomain =
                            securityFilterConfiguration.AllowChildSrcFromSameDomain;
                        existingConfiguration.AllowConnectionsFromSameDomain =
                            securityFilterConfiguration.AllowConnectionsFromSameDomain;
                        existingConfiguration.AllowFontsFromSameDomain =
                            securityFilterConfiguration.AllowFontsFromSameDomain;
                        existingConfiguration.AllowFormActionToSameDomain =
                            securityFilterConfiguration.AllowFormActionToSameDomain;
                        existingConfiguration.AllowFrameAncestorsFromSameDomain =
                            securityFilterConfiguration.AllowFrameAncestorsFromSameDomain;
                        existingConfiguration.AllowFramesFromSameDomain =
                            securityFilterConfiguration.AllowFramesFromSameDomain;
                        existingConfiguration.AllowImagesFromSameDomain =
                            securityFilterConfiguration.AllowImagesFromSameDomain;
                        existingConfiguration.AllowMediaFromSameDomain =
                            securityFilterConfiguration.AllowMediaFromSameDomain;
                        existingConfiguration.AllowPluginsFromSameDomain =
                            securityFilterConfiguration.AllowPluginsFromSameDomain;
                        existingConfiguration.AllowScriptsFromSameDomain =
                            securityFilterConfiguration.AllowScriptsFromSameDomain;
                        existingConfiguration.AllowStylesFromSameDomain =
                            securityFilterConfiguration.AllowStylesFromSameDomain;
                        existingConfiguration.AllowUnsafeEval = securityFilterConfiguration.AllowUnsafeEval;
                        existingConfiguration.AllowUnsafeInline = securityFilterConfiguration.AllowUnsafeInline;
                        existingConfiguration.AllowUnsafeInlineStyles =
                            securityFilterConfiguration.AllowUnsafeInlineStyles;
                        existingConfiguration.EnableContentSecurityPolicy =
                            securityFilterConfiguration.EnableContentSecurityPolicy;
                        existingConfiguration.EnableXContentTypeOptions =
                            securityFilterConfiguration.EnableXContentTypeOptions;
                        existingConfiguration.EnableXDownloadOptions =
                            securityFilterConfiguration.EnableXDownloadOptions;
                        existingConfiguration.EnableXFrameOptions = securityFilterConfiguration.EnableXFrameOptions;
                        existingConfiguration.XFrameOptionsPolicy = securityFilterConfiguration.XFrameOptionsPolicy;
                        existingConfiguration.CustomBaseUriSources = securityFilterConfiguration.CustomBaseUriSources;
                        existingConfiguration.CustomChildSources = securityFilterConfiguration.CustomChildSources;
                        existingConfiguration.CustomConnectionSources =
                            securityFilterConfiguration.CustomConnectionSources;
                        existingConfiguration.CustomFontSources = securityFilterConfiguration.CustomFontSources;
                        existingConfiguration.CustomFormActionSources =
                            securityFilterConfiguration.CustomFormActionSources;
                        existingConfiguration.CustomFrameAncestorsSources =
                            securityFilterConfiguration.CustomFrameAncestorsSources;
                        existingConfiguration.CustomFrameSources = securityFilterConfiguration.CustomFrameSources;
                        existingConfiguration.CustomImageSources = securityFilterConfiguration.CustomImageSources;
                        existingConfiguration.CustomMediaSources = securityFilterConfiguration.CustomMediaSources;
                        existingConfiguration.CustomPluginSources = securityFilterConfiguration.CustomPluginSources;
                        existingConfiguration.CustomScriptSources = securityFilterConfiguration.CustomScriptSources;
                        existingConfiguration.CustomStyleSources = securityFilterConfiguration.CustomStyleSources;
                    }

                    store.Save(existingConfiguration ?? securityFilterConfiguration);
                    
                    this.SecurityFilterConfiguration = securityFilterConfiguration;

                    System.Web.HttpRuntime.UnloadAppDomain();
                }
                catch (ArgumentNullException argumentNullException)
                {
                    this.log.Error(argumentNullException.Message, argumentNullException);
                }
            }
        }
    }
}