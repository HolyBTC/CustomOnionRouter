using Microsoft.AspNetCore.Server.Kestrel.Core;
using PingService = OnionRouter.Server.Api.GrpcServices.PingService;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
builder.Services.AddGrpc();
builder.Services.AddOpenApi("docs");
builder.WebHost.ConfigureKestrel(options =>
{
    options.ConfigureEndpointDefaults(lo => lo.Protocols = HttpProtocols.Http2);
});
var app = builder.Build();

app.MapOpenApi();
app.UseSwaggerUI(options =>
{
    options.SwaggerEndpoint("/openapi/docs.json", "OnionRouter.Server.Api");
});

app.MapGrpcService<PingService>();
app.MapControllers();

app.Run();