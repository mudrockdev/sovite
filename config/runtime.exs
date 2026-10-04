import Config

# The MTA starts in production releases, or anywhere SOVITE_START_MTA=1 is set
# (for example `SOVITE_START_MTA=1 SOVITE_CONFIG=... iex -S mix`). Sovite's own
# config files are not loaded when it is used as a dependency, so the MTA never
# starts inside another project by accident.
if config_env() == :prod or System.get_env("SOVITE_START_MTA") in ["1", "true"] do
  config :sovite, start_mta: true
end
