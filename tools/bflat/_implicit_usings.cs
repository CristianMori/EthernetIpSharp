// Synthetic equivalent of Microsoft.NET.Sdk's `<ImplicitUsings>enable</ImplicitUsings>`
// for net8.0. bflat does not read .csproj files, so the SDK's auto-added `global using`
// directives never materialize when compiling with bflat. Feeding this file alongside
// the project sources restores them.
global using System;
global using System.Collections.Generic;
global using System.IO;
global using System.Linq;
global using System.Net.Http;
global using System.Threading;
global using System.Threading.Tasks;
