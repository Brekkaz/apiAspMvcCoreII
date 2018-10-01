using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Data.Entity.Infrastructure;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using testAPI.Models;

namespace testAPI.Controllers
{

    [Produces("application/json")]
    [Route("api/Account")]
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public class AccountController : Controller
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IConfiguration _configuration;

        public AccountController(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _configuration = configuration;
        }

        // route: /api/account/login
        [HttpPost]
        [Route("Login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] UserInfo userInfo)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(userInfo.Email, userInfo.Password, isPersistent: false, lockoutOnFailure: false);
                if (result.Succeeded)
                {
                    return BuildToken(userInfo);
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return BadRequest(ModelState);
                }
            }
            else
            {
                return BadRequest(ModelState);
            }
        }

        // route: /api/account/create
        [Route("create")]
        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Create([FromBody] UserInfo model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = new ApplicationUser { UserName = model.Email, Email = model.Email };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (result.Succeeded)
            {
                return BuildToken(model);
            }
            else
            {
                return BadRequest("Username or password invalid");
            }

        }

        // route: /api/account/read
        [Route("read")]
        [HttpGet]
        public IEnumerable<ApplicationUser> Read()
        {
            return _userManager.Users.ToList();
        }

        // route: /api/account/read/5
        [Route("read/{id}")]
        [HttpGet]
        public IActionResult Read([FromRoute] string id)
        {
            if (id == null)
            {
                return BadRequest("id required");
            }

            var user = _userManager.Users.SingleOrDefault(u => u.Id == id);

            if (user == null)
            {
                return NotFound();
            }

            return Ok(user);
        }

        // route: /api/account/update/5
        [Route("update/{id}")]
        [HttpPut]
        public async Task<IActionResult> Update([FromRoute] string id, [FromBody] UserInfo user)
        {
            //TODO: AQUIIIIIIIIIIIIIIIIIIIIIIII

            /*if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!TestExists(id))
                {
                    return NotFound();
                }
                else
                {
                    throw;
                }
            }*/

            return NoContent();
        }

        // route: /api/account/delete/5
        [Route("delete/{id}")]
        [HttpDelete]
        public async Task<IActionResult> Delete([FromRoute] string id)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var user = _userManager.Users.SingleOrDefault(u => u.Id == id);

            if (user == null)
            {
                return NotFound();
            }

            await _userManager.DeleteAsync(user);

            return Ok(user);
        }

        private IActionResult BuildToken(UserInfo userInfo)
        {
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.UniqueName, userInfo.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Llave_super_secreta"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var expiration = DateTime.UtcNow.AddHours(1);

            JwtSecurityToken token = new JwtSecurityToken(
               issuer: "localhost:49820",
               audience: "localhost:49820",
               claims: claims,
               expires: expiration,
               signingCredentials: creds);

            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                expiration
            });

        }

    }
}