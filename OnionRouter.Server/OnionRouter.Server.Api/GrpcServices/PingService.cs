using Grpc.Core;
using OnionRouter.Contracts.Protos;

namespace OnionRouter.Server.Api.GrpcServices;

public class PingService : Contracts.Protos.PingService.PingServiceBase
{
    public override Task<PingReply> Ping(PingRequest request, ServerCallContext context)
    {
        return Task.FromResult(new PingReply());
    }
}