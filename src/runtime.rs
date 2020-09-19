use smol::Task;
use std::future::Future;
use std::thread;

pub fn smol_auto_run<T: Send + 'static>(start_future: impl Future<Output = T> + Send + 'static) {
    // Same number of threads as there are CPU cores.
    let num_threads = num_cpus::get();

    // A channel that sends the shutdown signal.
    let (s, r) = async_channel::bounded::<()>(1);
    let mut threads = Vec::new();

    // Create an executor thread pool.
    for _ in 0..num_threads {
        // Spawn an executor thread that waits for the shutdown signal.
        let r = r.clone();
        threads.push(thread::spawn(move || smol::run(r.recv())));
    }

    // No need to `run()`, now we can just block on the main future.
    smol::block_on(async {
        let _ = Task::spawn(start_future).await;
    });

    // Send a shutdown signal.
    drop(s);

    // Wait for threads to finish.
    for t in threads {
        let _ = t.join().unwrap();
    }
}
