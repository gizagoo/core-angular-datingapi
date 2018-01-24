using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using AutoMapper;
using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]
    public class AuthController : Controller
    {
        private readonly IAuthRepository _repo;
        private readonly IConfiguration _config;
        private readonly IMapper _mapper;
        public AuthController(IAuthRepository repo,
            IMapper mapper,
            IConfiguration config)
        {
            _mapper = mapper;
            _config = config;
            _repo = repo;

        }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody]UserForRegisterDto userForReg)
    {
        userForReg.Username = userForReg.Username.ToLower();

        if (await _repo.UserExists(userForReg.Username))
            ModelState.AddModelError("Username", "Username is already taken");

        // Validate Request
        if (!ModelState.IsValid)
            return BadRequest(ModelState);

        var userToCreate = new User
        {
            Username = userForReg.Username
        };

        var createUser = await _repo.Register(userToCreate, userForReg.Password);

        return StatusCode(201);
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] UserForLoginDto userForLogin)
    {
        var userFromRepo = await _repo.Login(userForLogin.Username.ToLower(), userForLogin.Password);

        if (userFromRepo == null)
            return Unauthorized();

        // generate Token
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_config.GetSection("AppSettings:Token").Value);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new System.Security.Claims.ClaimsIdentity(new Claim[]
            {
                    new Claim(ClaimTypes.NameIdentifier, userFromRepo.Id.ToString()),
                    new Claim(ClaimTypes.Name, userFromRepo.Username)
            }),
            Expires = System.DateTime.Now.AddDays(1),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha512Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);
        var tokenString = tokenHandler.WriteToken(token);

        var user = _mapper.Map<UserForListDto>(userFromRepo);

            return Ok(new { tokenString, user });
    }
}
}