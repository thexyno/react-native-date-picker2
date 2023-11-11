{
  description = "A simple poetry package";

  # Nixpkgs / NixOS version to use.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  inputs.poetry2nix = {
    url = "github:nix-community/poetry2nix";
    inputs.nixpkgs.follows = "nixpkgs";
  };
  outputs = { self, nixpkgs, poetry2nix }:
    let

      # to work with older version of flakes
      lastModifiedDate = self.lastModifiedDate or self.lastModified or "19700101";

      # Generate a user-friendly version number.
      version = builtins.substring 0 8 lastModifiedDate;

      # System types to support.
      supportedSystems = [ "x86_64-linux" "x86_64-darwin" "aarch64-linux" "aarch64-darwin" ];

      # Helper function to generate an attrset '{ x86_64-linux = f "x86_64-linux"; ... }'.
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;

      # Nixpkgs instantiated for supported system types.
      nixpkgsFor = forAllSystems (system: import nixpkgs { inherit system; });

    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgsFor.${system};
          inherit (poetry2nix.lib.mkPoetry2Nix { inherit pkgs; }) mkPoetryApplication;
        in
        {
          default =
            mkPoetryApplication {
              projectDir = ./.;
            };
        });
      container = forAllSystems (system:
        let
          pkgs = nixpkgsFor.${system};
          app = self.packages.${system}.default;
        in
        pkgs.dockerTools.buildImage {
          name = "AuthIsNotEasy";
          tag = "latest";
          copyToRoot = pkgs.buildEnv {
            name = "image-root";
            paths = [ app ];
            pathsToLink = [ "/bin" ];
          };

          runAsRoot = ''
            #!${pkgs.runtimeShell}
          '';

          config = {
            Cmd = [ "/bin/webctfchallenge" ];
            WorkingDir = "/";
          };


        }
      );
      devShell = forAllSystems (system:
        let pkgs = nixpkgsFor.${system}; in
        (pkgs.mkShell {
          buildInputs = [ pkgs.poetry ];
        }));
    };
}
