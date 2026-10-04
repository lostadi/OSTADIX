# disk-config.nix
# Disko declarative disk layout for bare-metal NixOS installation.
# Change device = to your actual drive (check with: lsblk)
{
  disko.devices = {
    disk = {
      main = {
        type   = "disk";
        device = "/dev/nvme0n1";
        content = {
          type = "gpt";
          partitions = {
            boot = {
              size = "512M";
              type = "EF00";
              content = {
                type       = "filesystem";
                format     = "vfat";
                mountpoint = "/boot";
              };
            };
            swap = {
              size = "16G";
              content = {
                type           = "swap";
                discardPolicy  = "both";
                randomEncryption = true;
              };
            };
            root = {
              size    = "100%";
              content = {
                type       = "filesystem";
                format     = "ext4";
                mountpoint = "/";
                extraArgs  = [ "-L" "ostadix-root" ];
              };
            };
          };
        };
      };
    };
  };
}
