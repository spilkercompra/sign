#See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 80
EXPOSE 443

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["Directory.Packages.props", "."]
COPY ["Directory.Build.props", "."]
COPY ["Directory.Build.targets", "."]
COPY ["NuGet.Config", "."]
COPY ["global.json", "."]
COPY ["eEvolution.Sign.Pkcs11.WebApi/eEvolution.Sign.Pkcs11.WebApi.csproj", "eEvolution.Sign.Pkcs11.WebApi/"]
RUN dotnet restore "eEvolution.Sign.Pkcs11.WebApi/eEvolution.Sign.Pkcs11.WebApi.csproj"
COPY . .
WORKDIR "/src/eEvolution.Sign.Pkcs11.WebApi"
RUN dotnet build "eEvolution.Sign.Pkcs11.WebApi.csproj" -c Release -o /app/build

FROM build AS publish
RUN dotnet publish "eEvolution.Sign.Pkcs11.WebApi.csproj" -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "eEvolution.Sign.Pkcs11.WebApi.dll"]