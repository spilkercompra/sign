// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace nGroup.Sign.Pkcs11.WebApi
{
  using Microsoft.AspNetCore.Builder;
  using nGroup.Sign.Pkcs11.Server;

  public class Program
  {
    public static void Main(string[] args)
    {
      var builder = WebApplication.CreateBuilder(args);

      // Add services to the container.
      builder.Services.AddControllers();
      builder.Services.AddOpenApiDocument();
      builder.Services.AddSingleton<IPkcs11TokenAccessApi, Pkcs11TokenAccessApi>();

      var app = builder.Build();

      if (app.Environment.IsDevelopment())
      {
        // Add OpenAPI 3.0 document serving middleware
        // Available at: http://localhost:<port>/swagger/v1/swagger.json
        app.UseOpenApi();

        // Add web UIs to interact with the document
        // Available at: http://localhost:<port>/swagger
        app.UseSwaggerUi();
      }

      app.UseHttpsRedirection();
      app.UseAuthorization();

      app.MapControllers();

      app.Run();
    }
  }
}