// Copyright © 2016 Jeroen Stemerdink.
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following
// conditions:
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
namespace EPi.Libraries.Security.Filters.Controllers
{
    using System.Web.Mvc;

    using EPi.Libraries.Security.Filters.Business.Configuration;
    using EPi.Libraries.Security.Filters.Models;

    using EPiServer.PlugIn;
    using EPiServer.Security;

    /// <summary>
    ///     Class HeaderConfigurationController.
    /// </summary>
    [GuiPlugIn(DisplayName = "Security Headers", Description = "Configure Security headers",
        Area = PlugInArea.AdminConfigMenu, Url = "/HeaderConfiguration", RequiredAccess = AccessLevel.Administer)]
    public class HeaderConfigurationController : Controller
    {
        /// <summary>
        ///     The index view.
        /// </summary>
        /// <returns>ActionResult.</returns>
        public ActionResult Index()
        {
            SecurityFilterConfiguration securityFilterConfiguration =
                SecurityConfigurationProvider.Instance.SecurityFilterConfiguration;

            return this.View(securityFilterConfiguration);
        }

        /// <summary>
        ///     Saves the specified security filter configuration.
        /// </summary>
        /// <param name="securityFilterConfiguration">The security filter configuration.</param>
        /// <returns>ActionResult.</returns>
        public ActionResult Save(SecurityFilterConfiguration securityFilterConfiguration)
        {
            SecurityConfigurationProvider.Instance.SaveConfiguration(securityFilterConfiguration);
            return this.View("Index", securityFilterConfiguration);
        }
    }
}