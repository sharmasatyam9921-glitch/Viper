"""Tests for StateMachine — pure-Python async state machine."""
import pytest
from core.orchestrator import StateMachine


class TestStateMachineBasicFlow:
    async def test_simple_two_node_graph_runs_to_end(self, state_machine):
        async def node_a(state):
            return {"visited_a": True}

        async def node_b(state):
            return {"visited_b": True, "task_complete": True}

        state_machine.add_node("a", node_a)
        state_machine.add_node("b", node_b)
        state_machine.add_edge("a", "b")
        state_machine.add_edge("b", "END")
        state_machine.set_entry("a")

        final = await state_machine.run({})
        assert final["visited_a"] is True
        assert final["visited_b"] is True

    async def test_entry_node_executed_first(self, state_machine):
        order = []

        async def first(state):
            order.append("first")
            return {}

        async def second(state):
            order.append("second")
            return {}

        state_machine.add_node("first", first)
        state_machine.add_node("second", second)
        state_machine.add_edge("first", "second")
        state_machine.add_edge("second", "END")
        state_machine.set_entry("first")

        await state_machine.run({})
        assert order == ["first", "second"]

    async def test_state_updates_accumulated(self, state_machine):
        async def node_x(state):
            return {"x": 10}

        async def node_y(state):
            return {"y": state["x"] * 2}

        state_machine.add_node("x", node_x)
        state_machine.add_node("y", node_y)
        state_machine.add_edge("x", "y")
        state_machine.add_edge("y", "END")
        state_machine.set_entry("x")

        final = await state_machine.run({})
        assert final["x"] == 10
        assert final["y"] == 20

    async def test_initial_state_preserved(self, state_machine):
        async def identity(state):
            return {}

        state_machine.add_node("id", identity)
        state_machine.add_edge("id", "END")
        state_machine.set_entry("id")

        initial = {"existing_key": "existing_value"}
        final = await state_machine.run(initial)
        assert final["existing_key"] == "existing_value"

    async def test_node_returning_none_does_not_crash(self, state_machine):
        async def noop(state):
            return None  # some nodes may return None

        state_machine.add_node("noop", noop)
        state_machine.add_edge("noop", "END")
        state_machine.set_entry("noop")

        final = await state_machine.run({"initial": True})
        assert final["initial"] is True


class TestStateMachineConditionalEdges:
    async def test_conditional_edge_routes_based_on_state(self, state_machine):
        async def router(state):
            return {}

        async def path_yes(state):
            return {"result": "yes"}

        async def path_no(state):
            return {"result": "no"}

        def condition(state):
            return "yes" if state.get("flag") else "no"

        state_machine.add_node("router", router)
        state_machine.add_node("yes", path_yes)
        state_machine.add_node("no", path_no)
        state_machine.add_conditional_edge("router", condition, {"yes": "yes", "no": "no"})
        state_machine.add_edge("yes", "END")
        state_machine.add_edge("no", "END")
        state_machine.set_entry("router")

        final_yes = await state_machine.run({"flag": True})
        assert final_yes["result"] == "yes"

        sm2 = StateMachine()
        sm2.add_node("router", router)
        sm2.add_node("yes", path_yes)
        sm2.add_node("no", path_no)
        sm2.add_conditional_edge("router", condition, {"yes": "yes", "no": "no"})
        sm2.add_edge("yes", "END")
        sm2.add_edge("no", "END")
        sm2.set_entry("router")
        final_no = await sm2.run({"flag": False})
        assert final_no["result"] == "no"

    async def test_conditional_edge_with_multiple_paths(self, state_machine):
        async def classify(state):
            return {}

        async def path_a(state):
            return {"path": "A"}

        async def path_b(state):
            return {"path": "B"}

        async def path_c(state):
            return {"path": "C"}

        def router_fn(state):
            return state.get("route", "C")

        state_machine.add_node("classify", classify)
        state_machine.add_node("A", path_a)
        state_machine.add_node("B", path_b)
        state_machine.add_node("C", path_c)
        state_machine.add_conditional_edge(
            "classify", router_fn, {"A": "A", "B": "B", "C": "C"}
        )
        for n in ["A", "B", "C"]:
            state_machine.add_edge(n, "END")
        state_machine.set_entry("classify")

        for route in ["A", "B", "C"]:
            sm = StateMachine()
            sm.add_node("classify", classify)
            sm.add_node("A", path_a)
            sm.add_node("B", path_b)
            sm.add_node("C", path_c)
            sm.add_conditional_edge("classify", router_fn, {"A": "A", "B": "B", "C": "C"})
            for n in ["A", "B", "C"]:
                sm.add_edge(n, "END")
            sm.set_entry("classify")
            final = await sm.run({"route": route})
            assert final["path"] == route


class TestStateMachineEdgeCases:
    async def test_no_entry_raises_runtime_error(self):
        sm = StateMachine()

        async def node(state):
            return {}

        sm.add_node("orphan", node)
        # Do NOT call set_entry

        with pytest.raises(RuntimeError, match="No entry node"):
            await sm.run({})

    async def test_unknown_node_raises_runtime_error(self, state_machine):
        state_machine.add_edge("a", "b")  # b doesn't exist as a node
        state_machine.set_entry("a")

        async def node_a(state):
            return {}

        state_machine.add_node("a", node_a)
        # 'b' is not a node and not "END"

        with pytest.raises(RuntimeError, match="Unknown node"):
            await state_machine.run({})

    async def test_max_steps_exceeded_sets_completion_reason(self, state_machine):
        """Cycles that exceed max_steps get forced to END with reason set."""
        call_count = [0]

        async def cycle_node(state):
            call_count[0] += 1
            return {}

        state_machine.add_node("cycle", cycle_node)
        state_machine.add_edge("cycle", "cycle")  # infinite loop
        state_machine.set_entry("cycle")

        # With max_iterations=1, max_steps = 1*3+20 = 23
        final = await state_machine.run({"max_iterations": 1})
        assert final.get("task_complete") is True
        assert final.get("completion_reason") == "max_steps_exceeded"

    async def test_node_exception_does_not_halt_machine(self, state_machine):
        """Node exceptions are caught and logged; error recorded in state['errors']."""
        async def broken(state):
            raise ValueError("something broke")

        state_machine.add_node("broken", broken)
        state_machine.add_edge("broken", "END")
        state_machine.set_entry("broken")

        # Should not raise; exception is logged and machine routes to END
        final = await state_machine.run({})
        # Error is appended to state['errors']
        assert "errors" in final
        assert len(final["errors"]) >= 1
        assert final["errors"][0]["node"] == "broken"
        assert "something broke" in final["errors"][0]["error"]

    async def test_add_node_and_edge_api(self, state_machine):
        """Basic structural API: add_node, add_edge, set_entry work without error."""

        async def dummy(state):
            return {}

        state_machine.add_node("n1", dummy)
        state_machine.add_node("n2", dummy)
        state_machine.add_edge("n1", "n2")
        state_machine.add_edge("n2", "END")
        state_machine.set_entry("n1")
        assert state_machine._entry == "n1"
        assert "n1" in state_machine._nodes
        assert "n2" in state_machine._nodes


class TestStateMachineMultipleRuns:
    async def test_same_machine_can_run_twice_with_fresh_state(self, state_machine):
        async def adder(state):
            return {"counter": state.get("counter", 0) + 1}

        state_machine.add_node("adder", adder)
        state_machine.add_edge("adder", "END")
        state_machine.set_entry("adder")

        r1 = await state_machine.run({})
        r2 = await state_machine.run({})
        assert r1["counter"] == 1
        assert r2["counter"] == 1  # fresh state each time

    async def test_initial_state_passed_through(self, state_machine):
        async def reader(state):
            return {"seen_initial": state.get("initial_val")}

        state_machine.add_node("reader", reader)
        state_machine.add_edge("reader", "END")
        state_machine.set_entry("reader")

        final = await state_machine.run({"initial_val": 42})
        assert final["seen_initial"] == 42
