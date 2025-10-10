FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
WORKDIR /app
EXPOSE 8080

FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src
COPY ["ManagementAPI/ManagementAPI.csproj", "ManagementAPI/"]
RUN dotnet restore "ManagementAPI/ManagementAPI.csproj"
COPY . .
WORKDIR "/src/ManagementAPI"
RUN dotnet publish -c Release -o /app/publish /p:UseAppHost=false

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .
ENV ASPNETCORE_URLS=http://+:8080
ENTRYPOINT ["dotnet", "ManagementAPI.dll"]
