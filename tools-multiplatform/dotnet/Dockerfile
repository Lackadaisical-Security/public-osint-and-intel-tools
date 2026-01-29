FROM mcr.microsoft.com/dotnet/sdk:6.0 AS build
WORKDIR /src

# Copy project file
COPY OSINTTools.csproj .

# Restore dependencies
RUN dotnet restore

# Copy source code
COPY . .

# Build application
RUN dotnet build -c Release -o /app/build

# Publish application
FROM build AS publish
RUN dotnet publish -c Release -o /app/publish

# Final stage
FROM mcr.microsoft.com/dotnet/runtime:6.0
WORKDIR /app

LABEL maintainer="Lackadaisical Security <security@lackadaisical-security.com>"
LABEL description="OSINT .NET Tools - Lackadaisical Security"

# Copy published application
COPY --from=publish /app/publish .

# Create output directory
RUN mkdir -p /app/output

# Create non-root user
RUN useradd -m -s /bin/bash osint && \
    chown -R osint:osint /app

USER osint

# Default command
ENTRYPOINT ["dotnet", "OSINTTools.dll"]
CMD ["--help"]
