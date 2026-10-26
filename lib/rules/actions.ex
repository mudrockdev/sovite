defmodule Sovite.Rules.Actions do
  @moduledoc """
  What a filter does with a message, by its score: the most severe
  action whose threshold the score reaches.

      iex> thresholds = %{reject: 15.0, add_header: 6.0, greylist: 4.0}
      iex> Sovite.Rules.Actions.decide(7.5, thresholds)
      :add_header
      iex> Sovite.Rules.Actions.decide(2.0, thresholds)
      :no_action

  The actions, most severe first:

    * `:reject` - refuse the message (`5xx`).
    * `:soft_reject` - refuse it for now (`451`), so the sender tries
      again later.
    * `:quarantine` - accept it, and hold it instead of delivering it.
    * `:rewrite_subject` - deliver it with its subject marked as spam.
    * `:add_header` - deliver it with header fields that mark it as spam.
    * `:greylist` - refuse it for now unless the sender has tried before.
    * `:no_action` - deliver it as it is.

  A threshold that is `nil` or `false` is not used.
  """

  @type action ::
          :reject
          | :soft_reject
          | :quarantine
          | :rewrite_subject
          | :add_header
          | :greylist
          | :no_action

  @type thresholds :: %{optional(action()) => float() | false | nil}

  @actions [:reject, :soft_reject, :quarantine, :rewrite_subject, :add_header, :greylist]
  @names Map.new(@actions ++ [:no_action], &{Atom.to_string(&1), &1})

  @doc "The actions that have thresholds, most severe first."
  @spec actions() :: [action()]
  def actions, do: @actions

  @doc "The action named `name` (`\"reject\"`, ...), or `:error`."
  @spec parse(String.t()) :: {:ok, action()} | :error
  def parse(name), do: Map.fetch(@names, name)

  @doc "The action for `score` with `thresholds`."
  @spec decide(number(), thresholds()) :: action()
  def decide(score, thresholds) do
    Enum.find(@actions, :no_action, fn action ->
      threshold = Map.get(thresholds, action)
      is_number(threshold) and score >= threshold
    end)
  end

  @doc """
  The least severe of `actions`: what one copy of a message for several
  recipients may get without one recipient losing mail another's
  settings would keep. `:no_action` for none.

      iex> Sovite.Rules.Actions.least_severe([:reject, :add_header, :rewrite_subject])
      :add_header
  """
  @spec least_severe([action()]) :: action()
  def least_severe([]), do: :no_action
  def least_severe(actions), do: Enum.max_by(actions, &severity/1)

  @doc "Whether `a` is more severe than `b`."
  @spec more_severe?(action(), action()) :: boolean()
  def more_severe?(a, b), do: severity(a) < severity(b)

  defp severity(:no_action), do: length(@actions)
  defp severity(action), do: Enum.find_index(@actions, &(&1 == action))
end
