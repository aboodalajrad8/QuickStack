using QuickStack.Models;

namespace QuickStack.Services.Auth.Templates;

public static class DockerTemplates
{
    private static string P(ProjectOptions o) => o.ProjectName;

    public static string Dockerfile(ProjectOptions o)
    {
        var p = P(o);
        return $$"""
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY ["src/Api/{{p}}.Api.csproj", "src/Api/"]
RUN dotnet restore "src/Api/{{p}}.Api.csproj"

COPY . .
WORKDIR "/src/src/Api"
RUN dotnet publish "{{p}}.Api.csproj" -c Release -o /app/publish

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
EXPOSE 80
EXPOSE 443
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "{{p}}.Api.dll"]
""";
    }

    public static string DockerCompose(ProjectOptions o)
    {
        return $$"""
services:
  api:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "5000:80"
      - "5001:443"
    environment:
      - ASPNETCORE_ENVIRONMENT=Development
      - ASPNETCORE_URLS=https://+:443;http://+:80
    volumes:
      - ~/.aspnet/https:/https:ro
""";
    }
}