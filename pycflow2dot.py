#! /usr/bin/python
# -*- coding: utf-8 -*-
"""Plot `cflow` output as graphs."""
# Copyright 2013-2017 Ioannis Filippidis
# Copyright 2010 unknown developer: https://code.google.com/p/cflow2dot/
# Copyright 2013 Dabaichi Valbendan
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
import os
import sys
import argparse
import subprocess
import locale
import re
import networkx as nx

# Comment out for customizing shapes
#     try:
#         import pydot
#     except:
#         pydot = None
pydot = None

debug_msg_verbosity = 0

copyright_msg = """
pycflow2dot v0.2.2 - licensed under GNU GPL v3
"""
# In small routine, fanin <= this limit and fanout <= this limit.
FANX_SMALL_LIMIT = 3

# Color Pattern
# COLORS = ['#eecc80', '#ccee80', '#80ccee', '#ee80cc', '#cc80ee', '#80eecc']
COLORS = ['#ffcc66', '#99ff66', '#66ffcc', '#6699ff', '#cc66ff', '#ff6699',
          '#cc9966', '#99cc66', '#66cc99', '#6699cc', '#9966cc', '#cc6699']

def dprint(verbosity, s):
    """Debug mode printing."""
    # TODO: make this a package
    if verbosity < debug_msg_verbosity:
        print(s)


def bytes2str(b):
    encoding = locale.getdefaultlocale()[1]
    return b.decode(encoding)


def get_max_space(lines):
    space = 0
    for i in range(0, len(lines)):
        if lines[i].startswith(space * 4 * ' '):
            i = 0
            space += 1
    return space


def get_name(line):
    name = ''
    for i in range(0, len(line)):
        if line[i] == ' ':
            pass
        elif line[i] == '(':
            break
        else:
            name += line[i]
    return name


def call_cflow(c_fnames, cflow, numbered_nesting=True, preprocess=False):
    cflow_cmd = [cflow]

    if numbered_nesting:
        cflow_cmd += ['-l']

    # None when -p passed w/o value
    if preprocess == None:
        cflow_cmd += ['--cpp']
    elif preprocess != False:
        cflow_cmd += ['--cpp=' + preprocess]

    cflow_cmd += c_fnames

    dprint(2, 'cflow command:\n\t' + str(cflow_cmd))

    cflow_data = subprocess.check_output(cflow_cmd)
    cflow_data = bytes2str(cflow_data)
    dprint(2, 'cflow returned:\n\n' + cflow_data)

    return cflow_data


def call_cat(cfo_fname, cat):
    cat_cmd = [cat, cfo_fname]

    dprint(2, 'cat command:\n\t' + str(cat_cmd) )

    cat_data = subprocess.check_output(cat_cmd)
    cat_data = bytes2str(cat_data)
    dprint(2, 'cat returned:\n\n' + cat_data)

    return cat_data


def cflow2nx(cflow_str, c_fname):
    lines = cflow_str.replace('\r', '').split('\n')

    g = nx.DiGraph()
    stack = dict()
    for line in lines:
        #dprint(2, line)

        # empty line ?
        if line == '':
            continue

        # defined in this file ?
        # apparently, this check is not needed: check this better

        # get file name and source line #
        matches = re.findall(' ([^ ]*):(\d*)>', line)
        if matches != []:
            (src_file_name, src_line_no) = matches[0]
            src_line_no = int(src_line_no)
        else:
            src_file_name = ''
            src_line_no = -1

        # trim
        s = re.sub(r'\(.*$', '', line)
        s = re.sub(r'^\{\s*', '', s)
        s = re.sub(r'\}\s*', r'\t', s)

        # where are we ?
        (nest_level, func_name) = re.split(r'\t', s)
        nest_level = int(nest_level)
        cur_node = is_reserved_by_dot(func_name)

        dprint(1, 'Found function:\n\t' + func_name
               + ',\n at depth:\n\t' + str(nest_level)
               + ',\n at src line:\n\t' + str(src_line_no))

        stack[nest_level] = cur_node

        # not already seen ?
        if cur_node not in g:
            g.add_node(cur_node, nest_level=nest_level,
                       src_line=src_line_no, src_file=src_file_name)
            dprint(0, 'New Node: ' + cur_node)

        # not root node ?
        if nest_level != 0:
            # then has predecessor
            pred_node = stack[nest_level - 1]

            # new edge ?
            if g.has_edge(pred_node, cur_node):
                # avoid duplicate edges
                # note DiGraph is so def

                # buggy: coloring depends on first occurrence ! (subjective)
                continue

            # add new edge
            g.add_edge(pred_node, cur_node)
            dprint(0, 'Found edge:\n\t' + pred_node + '--->' + cur_node)

    return g


def is_reserved_by_dot(word):
    reserved = {'graph', 'strict', 'digraph', 'subgraph', 'node', 'edge'}

    # dot is case-insensitive, according to:
    #   http://www.graphviz.org/doc/info/lang.html
    if word.lower() in reserved:
        word = word + '_'
    return word


def dot_preamble(c_fname, for_latex):
    if for_latex:
        c_fname = re.sub(r'_', r'\\\\_', c_fname)

    dot_str = 'digraph G {\n'
    dot_str += 'node [peripheries=2 style="filled,rounded" ' + \
        'fontname="Vera Sans Mono" color="' + COLORS[0] + '"];\n'
    dot_str += 'rankdir=LR;\n'
    dot_str += 'label="' + c_fname + '"\n'
    dot_str += 'main [shape=invhouse];\n'

    return dot_str


def choose_node_format(node, node_opts):

    nest_level = node_opts['nest_level']
    src_line = node_opts['src_line']
    src_file = node_opts['src_file']
    fanin = node_opts['fanin']
    fanout = node_opts['fanout']

    colors = COLORS
    sl = '\\\\'  # after fprintf \\ and after dot \, a single slash !

    # color, shape ?
    if nest_level == 0:
        color = colors[0]
        shape = 'invhouse'
    else:
        color = colors[nest_level % len(colors)]
        if fanout == 0:
            shape = 'box'
        elif fanin == 1 and fanout == 1:
            shape = 'ellipse'
        elif (fanin <= FANX_SMALL_LIMIT and
              fanout <= FANX_SMALL_LIMIT):
            shape = 'hexagon'
        else:
            shape = 'diamond'

    # fix underscores ?
    if node_opts['for_latex']:
        label = re.sub(r'_', r'\\\\_', node)
    else:
        label = node
    dprint(1, 'Label:\n\t: ' + label)

    # src line of def here ?
    if src_line != -1:
        label = label + '\\n'
        if node_opts['bind_c_inputs']:
            label += src_file + ':'
        label += str(src_line)
        label += ' [in=' + str(node_opts['fanin'])
        label += ', out=' + str(node_opts['fanout']) + ']'

    # multi-page pdf ?
    if node_opts['multi_page']:
        if src_line != -1:
            # label
            label = sl + 'descitem{' + node + '}\\n' + label
        else:
            # link only if LaTeX label will appear somewhere
            if node_opts['defined_somewhere']:
                label = sl + 'descref[' + label + ']{' + node + '}'

    dprint(1, 'Node dot label:\n\t: ' + label)

    return (label, color, shape)


def dot_format_node(node, node_opts):
    (label, color, shape) = choose_node_format(node, node_opts)
    dot_str = node
    dot_str += '[label="' + label + '" '
    dot_str += 'color="' + color + '" '
    dot_str += 'shape=' + shape + '];\n\n'

    return dot_str


def dot_format_edge(from_node, to_node, color):
    dot_str = 'edge [color="' + color + '"];\n\n'
    dot_str += from_node + '->' + to_node + '\n'

    return dot_str


def node_defined_in_other_src(node, other_graphs):
    defined_somewhere = False

    for graph in other_graphs:
        if node in graph:
            src_line = graph.node[node]['src_line']

            if src_line != -1:
                defined_somewhere = True

    return defined_somewhere


def dump_dot_wo_pydot(graph, other_graphs, c_fname, graph_opts):
    dot_str = dot_preamble(c_fname, graph_opts['for_latex'])

    rgraph = graph.copy().reverse()
    dprint(2, graph.edge)
    dprint(2, rgraph.edge)

    for node in graph:
        node_dict = graph.node[node]

        inflow_dict = rgraph.edge[node]
        outflow_dict = graph.edge[node]

        node_opts = {'nest_level' : node_dict['nest_level'],
                     'src_line' : node_dict['src_line'],
                     'src_file' : node_dict['src_file'],
                     'defined_somewhere' : node_defined_in_other_src(node, other_graphs),
                     'fanin' : len(inflow_dict),
                     'fanout' : len(outflow_dict),
                     'for_latex' : graph_opts['for_latex'],
                     'multi_page' : graph_opts['multi_page'],
                     'bind_c_inputs' : graph_opts['bind_c_inputs'] }

        dprint(2, 'node == ' + str(node_dict))
        dprint(2, 'in  ==> ' + str(node_opts['fanin']) + ' ' + str(inflow_dict))
        dprint(2, 'out ==> ' + str(node_opts['fanout']) + ' ' + str(outflow_dict))

        dot_str += dot_format_node(node, node_opts)

    for from_node, to_node in graph.edges_iter():
        # call order affects edge color, so use only black
        color = '#000000'
        dot_str += dot_format_edge(from_node, to_node, color)

    dot_str += '}\n'
    dprint(2, 'dot dump str:\n\n' + dot_str)

    return dot_str


def write_dot_file(dot_str, dot_fname):
    try:
        dot_path = dot_fname + '.dot'
        with open(dot_path, 'w') as fp:
            fp.write(dot_str)
            dprint(0, 'Dumped dot file.')
    except:
        raise Exception('Failed to save dot.')

    return dot_path


def write_graph2dot(graph, other_graphs, c_fname, img_fname, graph_opts):
    if pydot is None:
        dot_str = dump_dot_wo_pydot(graph, other_graphs, c_fname, graph_opts)
        dot_path = write_dot_file(dot_str, img_fname)
    else:
        # dump using networkx and pydot
        if hasattr(nx, "nx_pydot"):
            # pydot_graph = nx.nx_pydot.to_pydot(graph)
            pydot_graph = nx.drawing.nx_pydot.to_pydot(graph)
        else:
            pydot_graph = nx.to_pydot(graph)

        pydot_graph.set_splines('true')
        if layout == 'twopi':
            pydot_graph.set_ranksep(5)
            pydot_graph.set_root('main')
        else:
            pydot_graph.set_overlap(False)
            pydot_graph.set_rankdir('LR')

        dot_path = img_fname + '.dot'
        pydot_graph.write(dot_path, format='dot')

    return dot_path


def write_graphs2dot(graphs, c_fnames, img_fname, graph_opts):
    dot_paths = []
    counter = 0
    for graph, c_fname in zip(graphs, c_fnames):
        other_graphs = list(graphs)
        other_graphs.remove(graph)

        if img_fname == '@':
            cur_img_fname = 'cflow_' + os.path.basename(c_fname).replace('.', '_')
        else:
            cur_img_fname = img_fname + ('_%04u' % counter)
            counter += 1

        dot_paths += [write_graph2dot(graph, other_graphs, c_fname, cur_img_fname, graph_opts)]

    return dot_paths


def check_cflow_dot_availability(results_str):
    required = ['cflow', 'dot', 'cat']
    env_reqs = {'cflow':'CFLOW_CMD', 'dot':'DOT_CMD', 'cat':'CAT_CMD'}

    if pydot is None:
        shape_policy = 'original'
    else:
        shape_policy = 'pydot'
    results_str += ['shape policy : ' + shape_policy]

    dep_paths = []
    for dependency in required:
        # use environment variable value if exists
        # or search by which command.
        if env_reqs[dependency] in os.environ:
            env_req = env_reqs[dependency]
            path = os.environ[env_req]
            path = bytes2str(path)
            if not os.path.isfile(path):
                raise Exception(dependency +' not found in spite of $' + env_req + '.')
        else:
            path = subprocess.check_output(['which', dependency] )
            path = bytes2str(path)
            path = path.replace('\n', '')
            if path.find(dependency) < 0 :
                raise Exception(dependency +' not found in $PATH.')

        results_str += [dependency + ' : ' + path]
        dep_paths += [path]

    return dep_paths


def dot2img(dot_paths, img_format, layout, dot):

    print('start generating images [' + img_format + '] ... ...')

    if img_format != 'dot':
        for dot_path in dot_paths:
            img_fname = str(dot_path)
            img_fname = img_fname.replace('.dot', '.' + img_format)

            dot_cmd = [dot, '-K' + layout, '-T' + img_format, '-o', img_fname, dot_path]
            dprint(1, dot_cmd)

            subprocess.check_call(dot_cmd)

    print('completed.')


def latex_preamble_str():
    """Return string for LaTeX preamble.

    Used if you want to compile the SVGs stand-alone.

    If SVGs are included as part of LaTeX document, then copy required
    packages from this example to your own preamble.
    """

    latex = r"""
    \documentclass[12pt, final]{article}

    usepackage{mybasepreamble}
    % fix this !!! to become a minimal example

    \usepackage[paperwidth=25.5in, paperheight=28.5in]{geometry}

    \newcounter{desccount}
    \newcommand{\descitem}[1]{%
        	\refstepcounter{desccount}\label{#1}
    }
    \newcommand{\descref}[2][\undefined]{%
    	\ifx#1\undefined%
        \hyperref[#2]{#2}%
    	\else%
    	    \hyperref[#2]{#1}%
    	\fi%
    }%
    """
    return latex


def write_latex():
    latex_str = latex_preamble_str()


def parse_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('-i', '--input-filenames', nargs='+',
                        help='filename(s) of C source code files to be parsed.'
    )
    parser.add_argument('-b', '--bind-c-inputs', default=False, action='store_true',
                        help='bind all C inputs.'
    )
    parser.add_argument('-o', '--output-filename', default='@',
                        help='name of dot, svg, pdf etc file produced'
    )
    parser.add_argument('-f', '--output-format', default='svg',
                        choices=['dot', 'svg', 'pdf', 'png'],
                        help='output file format'
    )
    parser.add_argument('-l', '--latex-svg', default=False, action='store_true',
                        help='produce SVG for import to LaTeX via Inkscape'
    )
    parser.add_argument('-m', '--multi-page', default=False, action='store_true',
                        help='produce hyperref links between function calls '
                              + 'and their definitions. Used for multi-page '
                              + 'PDF output, where each page is a different '
                              + 'source file.'
    )
    parser.add_argument('-p', '--preprocess', default=False, nargs='?',
                        help='pass --cpp option to cflow, '
                        + 'invoking C preprocessor, optionally with args.'
    )
    parser.add_argument('-g', '--layout', default='dot',
                        choices=['dot', 'neato', 'twopi', 'circo', 'fdp', 'sfdp'],
                        help='graphviz layout algorithm.'
    )
    parser.add_argument('-x', '--excludes', nargs='+',
                        help='files listing functions to ignore.'
    )
    parser.add_argument('-I', '--input-cflowed-filenames', nargs='+',
                        help='filename(s) of cflow output files to be parsed.'
    )
    parser.add_argument('-k', '--keep-dot-files', default=False, action='store_true',
                       help='keep dot files.'
    )
    parser.add_argument('-v', '--version', default=False, action='store_true',
                        help='display version and settings.'
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    args = parser.parse_args()

    if args.input_cflowed_filenames and args.input_filenames:
        print("Please specify either -I option or -i option.")
        sys.exit(1)

    if args.bind_c_inputs and not args.input_filenames:
        print("Please specify -i option.")
        sys.exit(1)

    if args.bind_c_inputs and args.output_filename == '@':
        print("Please specify -o option.")
        sys.exit(1)

    return args


def rm_excluded_funcs(list_fnames, graphs):
    # nothing ignored ?
    if not list_fnames:
        return

    # for each file that contains ignored functions
    for list_fname in list_fnames:
        # load list of ignored functions
        rm_nodes = [line.strip() for line in open(list_fname).readlines() ]

        # remove comment lines and blank lines.
        comment_ptn = r"^[ 	]*#"
        reptn = re.compile(comment_ptn)
        rm_nodes = filter((lambda x: not ((x == '') or (reptn.match(x)))), rm_nodes)

        # delete them
        for graph in graphs:
            for node in rm_nodes:
                if node in graph:
                    graph.remove_node(node)


def do_version(avails_str):
    print(copyright_msg)
    print('---- environment ----')
    for avail in avails_str:
        print(avail)


def do_cat(c_fnames, cat):
    cflow_strs = []
    for c_fname in c_fnames:
        cur_str = call_cat(c_fname, cat)
        cflow_strs += [cur_str]
    return cflow_strs


def do_cflow(c_fnames, cflow, preproc, bind_c_inputs):
    if bind_c_inputs:
        cur_str = call_cflow(c_fnames, cflow, numbered_nesting=True,
                             preprocess=preproc)
        cflow_strs = [cur_str]
    else:
        cflow_strs = []
        for c_fname in c_fnames:
            cur_str = call_cflow([c_fname], cflow, numbered_nesting=True,
                                 preprocess=preproc)
            cflow_strs += [cur_str]
    return cflow_strs


def do_post_process(dot_paths, img_format, keep_dots):
    if keep_dots == False and img_format != 'dot':
        for dot_path in dot_paths:
            if os.path.isfile(dot_path):
                os.remove(dot_path)


def main():
    """Run cflow, parse output, produce dot and compile it into pdf | svg."""

    # input
    results_str = []
    (cflow, dot, cat) = check_cflow_dot_availability(results_str)

    args = parse_args()

    if args.version:
        do_version(results_str)
        sys.exit(0)

    input_is_cflowed = False
    c_fnames = args.input_filenames or []

    if args.input_cflowed_filenames:
        input_is_cflowed = True
        c_fnames = args.input_cflowed_filenames or []

    bind_c_inputs = args.bind_c_inputs
    img_format = args.output_format
    for_latex = args.latex_svg
    multi_page = args.multi_page
    img_fname = args.output_filename
    preproc = args.preprocess
    layout = args.layout
    exclude_list_fnames = args.excludes or []
    keep_dots = args.keep_dot_files

    dprint(0, 'C src files:\n\t' + str(c_fnames) + ", (extension '.c' omitted)\n"
           + 'img fname:\n\t' + str(img_fname) + '.' + img_format + '\n'
           + 'LaTeX export from Inkscape:\n\t' + str(for_latex) + '\n'
           + 'Multi-page PDF:\n\t' + str(multi_page))

    if input_is_cflowed:
        cflow_strs = do_cat(c_fnames, cat)
    else:
        cflow_strs = do_cflow(c_fnames, cflow, preproc, bind_c_inputs)
        if bind_c_inputs:
            c_fnames = [img_fname + '_binded']

    graphs = []
    for cflow_out, c_fname in zip(cflow_strs, c_fnames):
        cur_graph = cflow2nx(cflow_out, c_fname)
        graphs += [cur_graph]

    rm_excluded_funcs(exclude_list_fnames, graphs)

    graph_opts = {'for_latex' : for_latex, 'multi_page' : multi_page,
                  'layout' : layout, 'bind_c_inputs' : bind_c_inputs}
    dot_paths = write_graphs2dot(graphs, c_fnames, img_fname, graph_opts)

    dot2img(dot_paths, img_format, layout, dot)

    do_post_process(dot_paths, img_format, keep_dots)

    sys.exit(0)

if __name__ == "__main__":
    main()
