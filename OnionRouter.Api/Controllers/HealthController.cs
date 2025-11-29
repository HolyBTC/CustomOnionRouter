using Microsoft.AspNetCore.Mvc;

namespace OnionRouter.Api.Controllers;

[Route("api/health")]
[ApiController]
public class HealthController : ControllerBase
{
    [HttpPost]
    public IActionResult Get()
    {
        return NoContent();
    }
}