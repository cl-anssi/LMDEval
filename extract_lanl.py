import argparse
import gzip

import pandas as pd




def extract_auth_events(auth_file, redteam_events, out_path, buf_size=10000):
	'''
	Reads the auth.txt.gz file and writes the preprocessed dataset.
	Each line of the preprocessed dataset has the following fields:
	- timestamp (int): the original timestamp.
	- user (str): name of the destination user.
	- source (str): name of the source computer.
	- destination (str): name of the destination computer.

	Arguments
	---------
	auth_file : str
		Path to the auth.txt.gz file.
	redteam_events : set
		Set of red team events.
		Each event is a (timestamp, user, source computer, destination
		computer) tuple.
	out_path : str
		Path to the output file.
	buf_size : int, default=10000
		Maximum number of lines stored in memory.
		When the buffer is full, the stored lines are flushed to disk.

	'''

	lines = []
	with gzip.open(auth_file, 'rt') as file:
		for line in file:
			fields = line.strip().split(',')
			if fields[7] != 'LogOn' or fields[3] == fields[4]:
				# Keep only remote LogOn events
				continue
			ts, u_src, u_dst, c_src, c_dst, ap, lt = fields[:7]
			lab = int((int(ts), u_dst, c_src, c_dst) in redteam_events)
			lines.append(','.join([ts, u_dst, c_src, c_dst, str(lab)]))
			if len(lines) >= buf_size:
				write_lines(lines, out_path)
				lines = []
	write_lines(lines, out_path)

def extract_redteam_events(redteam_file):
	'''
	Reads the redteam.txt.gz file and returns its contents as a set.
	Each element of the set is a (timestamp, user, source computer, destination
	computer) tuple.

	Arguments
	---------
	redteam_file : str
		Path to the redteam.txt.gz file.

	Returns
	-------
	redteam_events : set
		Extracted events.

	'''

	redteam = pd.read_csv(redteam_file, names=('ts', 'usr', 'src', 'dst'))
	return set([
		(ts, usr, src, dst)
		for ts, usr, src, dst in zip(
			redteam['ts'], redteam['usr'], redteam['src'], redteam['dst']
		)
	])

def write_lines(lines, out_path):
	'''
	Writes lines to a file.

	Arguments
	---------
	lines : iterable[str]
		Lines to write.
		A newline character will be appended to each line.
	out_path : str
		Path to the output file.

	'''

	with open(out_path, 'a+') as file:
		for line in lines:
			file.write(line + '\n')

if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument(
		'auth_file',
		help='Path to auth.txt.gz'
	)
	parser.add_argument(
		'redteam_file',
		help='Path to redteam.txt.gz'
	)
	parser.add_argument(
		'--buf-size', '-b',
		type=int, default=10000,
		help=(
			'Maximum number of lines stored in memory. '
			'When the buffer is full, the stored lines are flushed to disk.'
		)
	)
	parser.add_argument(
		'--output', '-o',
		default='lanl.csv',
		help='Path to the output file.'
	)
	args = parser.parse_args()

	redteam_events = extract_redteam_events(args.redteam_file)
	extract_auth_events(
		args.auth_file, redteam_events, args.output, buf_size=args.buf_size
	)