// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE.txt file in the project root for more information.

namespace eEvolution.Sign.Pkcs11.Server
{
  using System;

  public record TokenInfos(
    LibraryInfo Library, 
    List<SlotInfo> Slots, 
    List<TokenInfo> Tokens);

  public record LibraryInfo
  {
    public string? CryptokiVersion { get; init; }

    public string? ManufacturerId { get; init; }

    public ulong Flags { get; init; }

    public string? LibraryDescription { get; init; }

    public string? LibraryVersion { get; init; }
  }

  public record SlotInfo
  {
    public ulong SlotId { get; init; }

    public string? SlotDescription { get; init; }

    public string? ManufacturerId { get; init; }

    public SlotFlags? SlotFlags { get; init; }

    public string? HardwareVersion { get; init; }

    public string? FirmwareVersion { get; init; }
  }

  public record SlotFlags
  {
    public ulong Flags { get; init; }

    public bool TokenPresent { get; init; }

    public bool RemovableDevice { get; init; }

    public bool HardwareSlot { get; init; }
  }

  public record TokenInfo
  {
    public ulong SlotId { get; init; }

    public string? Label { get; init; }

    public string? ManufacturerId { get; init; }

    public string? Model { get; init; }

    public string? SerialNumber { get; init; }

    public TokenFlags? TokenFlags { get; init; }

    public ulong MaxSessionCount { get; init; }

    public ulong SessionCount { get; init; }

    public ulong MaxRwSessionCount { get; init; }

    public ulong RwSessionCount { get; init; }

    public ulong MaxPinLen { get; init; }

    public ulong MinPinLen { get; init; }

    public ulong TotalPublicMemory { get; init; }

    public ulong FreePublicMemory { get; init; }

    public ulong TotalPrivateMemory { get; init; }

    public ulong FreePrivateMemory { get; init; }

    public string? HardwareVersion { get; init; }

    public string? FirmwareVersion { get; init; }

    public string? UtcTimeString { get; init; }

    public DateTime? UtcTime { get; init; }
  }

  public record TokenFlags
  {
    public ulong Flags { get; init; }

    public bool Rng { get; init; }

    public bool WriteProtected { get; init; }

    public bool LoginRequired { get; init; }

    public bool UserPinInitialized { get; init; }

    public bool RestoreKeyNotNeeded { get; init; }

    public bool ClockOnToken { get; init; }

    public bool ProtectedAuthenticationPath { get; init; }

    public bool DualCryptoOperations { get; init; }

    public bool TokenInitialized { get; init; }

    public bool SecondaryAuthentication { get; init; }

    public bool UserPinCountLow { get; init; }

    public bool UserPinFinalTry { get; init; }

    public bool UserPinLocked { get; init; }

    public bool UserPinToBeChanged { get; init; }

    public bool SoPinCountLow { get; init; }

    public bool SoPinFinalTry { get; init; }

    public bool SoPinLocked { get; init; }

    public bool SoPinToBeChanged { get; init; }
  }
}