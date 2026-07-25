let meta = #{
    name: "et-parity-parallel",
    description: "Parallel G005 reconnect / G006 tunnels / G007 jumphost tracks then integrate-test",
    phases: [
        #{ title: "Inventory", detail: "freeze track list from tree" },
        #{ title: "Parallel tracks", detail: "worktree-isolated implementers" },
        #{ title: "Integrate", detail: "single-tree regression" },
    ],
};

let track_schema = #{
    "type": "object",
    "required": ["track", "summary", "tests", "status"],
    "properties": #{
        "track": #{ "type": "string" },
        "summary": #{ "type": "string" },
        "tests": #{ "type": "string" },
        "status": #{ "type": "string" },
        "gaps": #{ "type": "string" },
    },
};

let integrate_schema = #{
    "type": "object",
    "required": ["ok", "summary", "commands"],
    "properties": #{
        "ok": #{ "type": "boolean" },
        "summary": #{ "type": "string" },
        "commands": #{ "type": "string" },
    },
};

phase("Inventory");
let inv = agent(
    "Inventory /home/minpeter/github.com/minpeter/et.rs for G005 reconnect, G006 tunnels, G007 jumphost. "
        + "Use list_dir/grep/read_file only. Return track list: reconnect, tunnels, jumphost with "
        + "whether shipped tests exist. status=ready|gap. Keep summary under 500 chars.",
    #{
        label: "inventory",
        capability_mode: "read-only",
        output_schema: track_schema,
    },
);
if inv == () || !inv.success {
    log("inventory agent failed; continuing with fixed tracks");
}

phase("Parallel tracks");
let jobs = [];

let p_reconnect = "";
p_reconnect += "Track RECONNECT (G005) on et.rs at /home/minpeter/github.com/minpeter/et.rs. ";
p_reconnect += "Ensure shipped reconnect tests pass: cargo test -p et --test reconnect_end_to_end ";
p_reconnect += "and unit coverage for RETURNING_CLIENT/catchup. Fix only real failures in reconnect ";
p_reconnect += "paths (reconnect.rs, connection_recovery, client_terminal_loop). Do not reimplement ";
p_reconnect += "under test. Report {track,summary,tests,status,gaps}.";
jobs.push(#{
    prompt: p_reconnect,
    label: "track-reconnect",
    capability_mode: "all",
    isolation_worktree: true,
    output_schema: track_schema,
});

let p_tunnels = "";
p_tunnels += "Track TUNNELS (G006) on et.rs at /home/minpeter/github.com/minpeter/et.rs. ";
p_tunnels += "Ensure local/reverse TCP, Unix, SSH-agent forwarding tests pass: ";
p_tunnels += "cargo test -p et --test tunnels_end_to_end and cargo test -p et-net --test forward. ";
p_tunnels += "Extend shipped forward_* and tunnel code only if tests fail. Report ";
p_tunnels += "{track,summary,tests,status,gaps}.";
jobs.push(#{
    prompt: p_tunnels,
    label: "track-tunnels",
    capability_mode: "all",
    isolation_worktree: true,
    output_schema: track_schema,
});

let p_jump = "";
p_jump += "Track JUMPHOST (G007) on et.rs at /home/minpeter/github.com/minpeter/et.rs. ";
p_jump += "Implement SSH ProxyJump via --jumphost as ssh -J (build_invocation already supports -J). ";
p_jump += "Reject --jserverfifo and option-injection jumphost values clearly. Keep payload.jumphost=false ";
p_jump += "for SSH-only bootstrap; server may still reject ET-native jumphost:true. Add/adjust tests in ";
p_jump += "client_bootstrap and bootstrap unit tests. Report {track,summary,tests,status,gaps}.";
jobs.push(#{
    prompt: p_jump,
    label: "track-jumphost",
    capability_mode: "all",
    isolation_worktree: true,
    output_schema: track_schema,
});

let results = parallel(jobs);
let n_ok = 0;
let i = 0;
for r in results {
    if r != () && r.success {
        n_ok += 1;
        log("track ok: " + r.output.track + " status=" + r.output.status);
    } else {
        log("track failed slot " + i.to_string());
    }
    i += 1;
}
log(n_ok.to_string() + "/3 parallel tracks returned success");

phase("Integrate");
let p_int = "";
p_int += "Integrate et.rs at /home/minpeter/github.com/minpeter/et.rs after parallel tracks. ";
p_int += "Work on the MAIN workspace tree (not orphan worktrees). Run: ";
p_int += "(1) cargo test -p et --test reconnect_end_to_end ";
p_int += "(2) cargo test -p et --test tunnels_end_to_end ";
p_int += "(3) cargo test -p et --test client_bootstrap ";
p_int += "(4) cargo test --workspace twice if time allows else once. ";
p_int += "Fix any integration regressions on the main tree. ";
p_int += "Return {ok,summary,commands} with ok=true only if tests exit 0.";
let integ = agent(
    p_int,
    #{
        label: "integrate",
        capability_mode: "all",
        isolation_worktree: false,
        output_schema: integrate_schema,
    },
);

if integ == () || !integ.success {
    complete(#{
        summary: "integrate agent failed",
        parallel_ok: n_ok,
        integrate_ok: false,
    });
}

complete(#{
    summary: integ.output.summary,
    parallel_ok: n_ok,
    integrate_ok: integ.output.ok,
    commands: integ.output.commands,
});
