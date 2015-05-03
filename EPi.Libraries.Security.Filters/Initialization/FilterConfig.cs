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
using System.Web.Mvc;

using EPi.Libraries.Security.Filters.Business;
using EPi.Libraries.Security.Filters.Business.Configuration;
using EPi.Libraries.Security.Filters.Models;

using NWebsec.Mvc.HttpHeaders;
using NWebsec.Mvc.HttpHeaders.Csp;

namespace EPi.Libraries.Security.Filters.Initialization
{
    /// <summary>
    /// Class FilterConfig.
    /// </summary>
    public static class FilterConfig
    {
        /// <summary>
        /// The security filter configuration
        /// </summary>
        private static readonly SecurityFilterConfiguration SecurityFilterConfiguration =
            SecurityConfigurationProvider.Instance.SecurityFilterConfiguration;

        /// <summary>
        /// Registers the global filters.
        /// </summary>
        /// <param name="filters">The filters.</param>
        public static void RegisterGlobalFilters(GlobalFilterCollection filters)
        {
            if (filters == null)
            {
                return;
            }

            AddSecurityFilters(filters);
            AddContentSecurityPolicyFilters(filters);

            if (SecurityFilterConfiguration.DisableVersionHeaders)
            {
                filters.Add(new RemoveVersionHeaders());
            }
            
        }

        /// <summary>
        ///     Several NWebsec Security Filters are added here.
        /// </summary>
        private static void AddSecurityFilters(GlobalFilterCollection filters)
        {
            // X-Content-Type-Options
            if (SecurityFilterConfiguration.EnableXContentTypeOptions)
            {
                filters.Add(new XContentTypeOptionsAttribute());
            }

            // X-Download-Options
            if (SecurityFilterConfiguration.EnableXDownloadOptions)
            {
                filters.Add(new XDownloadOptionsAttribute());
            }

            // X-Frame-Options
            if (!SecurityFilterConfiguration.EnableXFrameOptions)
            {
                return;
            }

            XFrameOptionsPolicy policy;

            switch (SecurityFilterConfiguration.XFrameOptionsPolicy)
            {
                case SecurityFilterConfiguration.Deny:
                    policy = XFrameOptionsPolicy.Deny;
                    break;
                case SecurityFilterConfiguration.Disabled:
                    policy = XFrameOptionsPolicy.Disabled;
                    break;
                default:
                    policy = XFrameOptionsPolicy.SameOrigin;
                    break;
            }

            filters.Add(new XFrameOptionsAttribute { Policy = policy });
        }

        /// <summary>
        ///     Adds the Content-Security-Policy (CSP) and/or Content-Security-Policy-Report-Only HTTP headers.
        /// </summary>
        private static void AddContentSecurityPolicyFilters(GlobalFilterCollection filters)
        {
            // Content-Security-Policy
            if (!SecurityFilterConfiguration.EnableContentSecurityPolicy)
            {
                return;
            }

            filters.Add(new CspAttribute());

            // base-uri
            CspBaseUriAttribute cspBaseUriAttribute = new CspBaseUriAttribute()
                                                          {
                                                              Self =
                                                                  SecurityFilterConfiguration
                                                                  .AllowBaseUriFromSameDomain
                                                          };

            if (!string.IsNullOrWhiteSpace(SecurityFilterConfiguration.CustomBaseUriSources))
            {
                cspBaseUriAttribute.CustomSources = SecurityFilterConfiguration.CustomBaseUriSources.Replace(Environment.NewLine, " ");
            }

            filters.Add(cspBaseUriAttribute);

            // child-src
            CspChildSrcAttribute cspChildSrcAttribute = new CspChildSrcAttribute()
                                                            {
                                                                Self =
                                                                    SecurityFilterConfiguration
                                                                    .AllowChildSrcFromSameDomain
                                                            };

            if (!string.IsNullOrWhiteSpace(SecurityFilterConfiguration.CustomChildSources))
            {
                cspChildSrcAttribute.CustomSources = SecurityFilterConfiguration.CustomChildSources.Replace(Environment.NewLine, " ");
            }

            filters.Add(cspChildSrcAttribute);

            // connect-src
            CspConnectSrcAttribute cspConnectSrcAttribute = new CspConnectSrcAttribute
                                                                {
                                                                    Self =
                                                                        SecurityFilterConfiguration
                                                                        .AllowConnectionsFromSameDomain
                                                                };

            if (!string.IsNullOrWhiteSpace(SecurityFilterConfiguration.CustomChildSources))
            {
                cspConnectSrcAttribute.CustomSources = SecurityFilterConfiguration.CustomConnectionSources.Replace(Environment.NewLine, " ");
            }

            filters.Add(cspConnectSrcAttribute);

            // font-src
            CspFontSrcAttribute cspFontSrcAttribute = new CspFontSrcAttribute
                                                          {
                                                              Self =
                                                                  SecurityFilterConfiguration
                                                                  .AllowFontsFromSameDomain
                                                          };

            if (!string.IsNullOrWhiteSpace(SecurityFilterConfiguration.CustomFontSources))
            {
                cspFontSrcAttribute.CustomSources = SecurityFilterConfiguration.CustomFontSources.Replace(Environment.NewLine, " ");
            }

            filters.Add(cspFontSrcAttribute);

            // form-action
            CspFormActionAttribute cspFormActionAttribute = new CspFormActionAttribute
                                                                {
                                                                    Self =
                                                                        SecurityFilterConfiguration
                                                                        .AllowFormActionToSameDomain
                                                                };

            if (!string.IsNullOrWhiteSpace(SecurityFilterConfiguration.CustomFormActionSources))
            {
                cspFormActionAttribute.CustomSources = SecurityFilterConfiguration.CustomFormActionSources.Replace(Environment.NewLine, " ");
            }

            filters.Add(cspFormActionAttribute);

            // frame-src
            CspFrameSrcAttribute cspFrameSrcAttribute = new CspFrameSrcAttribute
                                                            {
                                                                Self =
                                                                    SecurityFilterConfiguration
                                                                    .AllowFramesFromSameDomain
                                                            };

            if (!string.IsNullOrWhiteSpace(SecurityFilterConfiguration.CustomFrameSources))
            {
                cspFrameSrcAttribute.CustomSources = SecurityFilterConfiguration.CustomFrameSources.Replace(Environment.NewLine, " ");
            }

            filters.Add(cspFrameSrcAttribute);

            // frame-ancestors
            CspFrameAncestorsAttribute cspFrameAncestorsAttribute = new CspFrameAncestorsAttribute
                                                                        {
                                                                            Self =
                                                                                SecurityFilterConfiguration
                                                                                .AllowFrameAncestorsFromSameDomain
                                                                        };

            if (!string.IsNullOrWhiteSpace(SecurityFilterConfiguration.CustomFrameAncestorsSources))
            {
                cspFrameAncestorsAttribute.CustomSources = SecurityFilterConfiguration.CustomFrameAncestorsSources.Replace(Environment.NewLine, " ");
            }

            filters.Add(cspFrameAncestorsAttribute);

            // img-src
            CspImgSrcAttribute cspImgSrcAttribute = new CspImgSrcAttribute
                                                        {
                                                            Self =
                                                                SecurityFilterConfiguration
                                                                .AllowImagesFromSameDomain
                                                        };

            if (!string.IsNullOrWhiteSpace(SecurityFilterConfiguration.CustomImageSources))
            {
                cspImgSrcAttribute.CustomSources = SecurityFilterConfiguration.CustomImageSources.Replace(Environment.NewLine, " ");
            }

            filters.Add(cspImgSrcAttribute);

            // script-src
            CspScriptSrcAttribute cspScriptSrcAttribute = new CspScriptSrcAttribute
                                                              {
                                                                  Self =
                                                                      SecurityFilterConfiguration
                                                                      .AllowScriptsFromSameDomain,
                                                                  UnsafeEval =
                                                                      SecurityFilterConfiguration
                                                                      .AllowUnsafeEval,
                                                                  UnsafeInline =
                                                                      SecurityFilterConfiguration
                                                                      .AllowUnsafeInline
                                                              };

            if (!string.IsNullOrWhiteSpace(SecurityFilterConfiguration.CustomScriptSources))
            {
                cspScriptSrcAttribute.CustomSources = SecurityFilterConfiguration.CustomScriptSources.Replace(Environment.NewLine, " ");
            }

            filters.Add(cspScriptSrcAttribute);

            // media-src
            CspMediaSrcAttribute cspMediaSrcAttribute = new CspMediaSrcAttribute
                                                            {
                                                                Self =
                                                                    SecurityFilterConfiguration
                                                                    .AllowMediaFromSameDomain
                                                            };

            if (!string.IsNullOrWhiteSpace(SecurityFilterConfiguration.CustomMediaSources))
            {
                cspMediaSrcAttribute.CustomSources = SecurityFilterConfiguration.CustomMediaSources.Replace(Environment.NewLine, " ");
            }

            filters.Add(cspMediaSrcAttribute);

            // object-src
            CspObjectSrcAttribute cspObjectSrcAttribute = new CspObjectSrcAttribute
                                                              {
                                                                  Self =
                                                                      SecurityFilterConfiguration
                                                                      .AllowPluginsFromSameDomain
                                                              };

            if (!string.IsNullOrWhiteSpace(SecurityFilterConfiguration.CustomPluginSources))
            {
                cspObjectSrcAttribute.CustomSources = SecurityFilterConfiguration.CustomPluginSources.Replace(Environment.NewLine, " ");
            }

            filters.Add(cspObjectSrcAttribute);

            // style-src
            CspStyleSrcAttribute cspStyleSrcAttribute = new CspStyleSrcAttribute
                                                            {
                                                                Self =
                                                                    SecurityFilterConfiguration
                                                                    .AllowStylesFromSameDomain,
                                                                UnsafeInline =
                                                                    SecurityFilterConfiguration
                                                                    .AllowUnsafeInlineStyles
                                                            };

            if (!string.IsNullOrWhiteSpace(SecurityFilterConfiguration.CustomStyleSources))
            {
                cspStyleSrcAttribute.CustomSources = SecurityFilterConfiguration.CustomStyleSources.Replace(Environment.NewLine, " ");
            }

            filters.Add(cspStyleSrcAttribute);
        }
    }
}